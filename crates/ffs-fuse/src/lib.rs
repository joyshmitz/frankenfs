#![forbid(unsafe_code)]
//! FUSE adapter for FrankenFS.
//!
//! This crate is a thin translation layer: kernel FUSE requests arrive via the
//! `fuser` crate, get forwarded to a [`FsOps`] implementation (from `ffs-core`),
//! and errors are mapped through [`FfsError::to_errno()`].
//!
//! See [`per_core::PerCoreDispatcher`] for thread-per-core dispatch routing.

pub mod per_core;

use asupersync::Cx;
use ffs_core::{
    BackpressureDecision, BackpressureGate, FiemapExtent, FileType as FfsFileType, FsOps,
    InodeAttr, RequestOp, RequestScope, SeekWhence, SetAttrRequest, XattrSetMode,
};
use ffs_error::FfsError;
use ffs_types::InodeNumber;
use fuser::{
    FileAttr, FileType, Filesystem, KernelConfig, MountOption, ReplyAttr, ReplyCreate, ReplyData,
    ReplyDirectory, ReplyEmpty, ReplyEntry, ReplyIoctl, ReplyLseek, ReplyOpen, ReplyStatfs,
    ReplyWrite, ReplyXattr, Request, TimeOrNow,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::ffi::OsStr;
use std::io::Write;
use std::os::raw::c_int;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{Receiver, SyncSender, sync_channel};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime};
use thiserror::Error;
use tracing::{debug, info, trace, warn};

/// Default TTL for cached attributes and entries.
///
/// Read-only images are immutable, so a generous TTL is safe.
const ATTR_TTL: Duration = Duration::from_secs(60);
const MIN_SEQUENTIAL_READS_FOR_BATCH: u32 = 2;
const COALESCED_FETCH_MULTIPLIER: u32 = 4;
const MAX_COALESCED_READ_SIZE: u32 = 256 * 1024;
const MAX_PENDING_READAHEAD_ENTRIES: usize = 64;
const MAX_ACCESS_PREDICTOR_ENTRIES: usize = 4096;
const BACKPRESSURE_THROTTLE_DELAY: Duration = Duration::from_millis(5);
const XATTR_FLAG_CREATE: i32 = 0x1;
const XATTR_FLAG_REPLACE: i32 = 0x2;
const FS_IOC_FIEMAP: u32 = 0xC020_660B;
const FIEMAP_HEADER_SIZE: usize = 32;
const FIEMAP_EXTENT_SIZE: usize = 56;
const FIEMAP_FLAG_SYNC: u32 = 0x0000_0001;
#[cfg(test)]
const FIEMAP_FLAG_XATTR: u32 = 0x0000_0002;
const FIEMAP_SUPPORTED_FLAGS: u32 = FIEMAP_FLAG_SYNC;
/// `EXT4_IOC_GETFLAGS` = `_IOR('f', 1, long)` on x86_64.
///
/// Linux FUSE fileattr plumbing still transfers these flags as `u32`
/// buffers, so the FUSE handler must not assume an 8-byte payload.
const EXT4_IOC_GETFLAGS: u32 = 0x8008_6601;
/// `EXT4_IOC_GETVERSION` = `_IOR('f', 3, long)` on x86_64.
///
/// The ext4 generation value is likewise surfaced through a `u32` payload in
/// the FUSE fileattr path.
const EXT4_IOC_GETVERSION: u32 = 0x8008_6603;
/// `EXT4_IOC_SETFLAGS` = `_IOW('f', 2, long)` on x86_64.
const EXT4_IOC_SETFLAGS: u32 = 0x4008_6602;
/// `EXT4_IOC_MOVE_EXT` = `_IOWR('f', 15, struct move_extent)` on x86_64.
const EXT4_IOC_MOVE_EXT: u32 = 0xC028_660F;
const FIEMAP_START_OFFSET: usize = 0;
const FIEMAP_LENGTH_OFFSET: usize = 8;
const FIEMAP_FLAGS_OFFSET: usize = 16;
const FIEMAP_MAPPED_EXTENTS_OFFSET: usize = 20;
const FIEMAP_EXTENT_COUNT_OFFSET: usize = 24;
const MOVE_EXT_SIZE: usize = 40;
const MOVE_EXT_RESERVED_OFFSET: usize = 0;
const MOVE_EXT_DONOR_FD_OFFSET: usize = 4;
const MOVE_EXT_ORIG_START_OFFSET: usize = 8;
const MOVE_EXT_DONOR_START_OFFSET: usize = 16;
const MOVE_EXT_LEN_OFFSET: usize = 24;
const MOVE_EXT_MOVED_LEN_OFFSET: usize = 32;
const MOVE_EXT_PAGE_SIZE_BYTES: u64 = 4096;
const EXT4_MOVE_EXT_MAX_BLOCKS: u64 = 0xFFFF_FFFF;

// ── Error type ──────────────────────────────────────────────────────────────

#[derive(Debug, Error)]
pub enum FuseError {
    #[error("invalid mountpoint: {0}")]
    InvalidMountpoint(String),
    #[error("mount I/O error: {0}")]
    Io(#[from] std::io::Error),
}

// ── FUSE error context ─────────────────────────────────────────────────────

/// Structured error context for FUSE operation failures.
///
/// Captures the operation name, inode, optional offset, and the underlying
/// error. Used to produce consistent, structured tracing for every FUSE
/// error reply.
pub struct FuseErrorContext<'a> {
    pub error: &'a FfsError,
    pub operation: &'static str,
    pub ino: u64,
    pub offset: Option<u64>,
}

impl FuseErrorContext<'_> {
    /// Log this error context via tracing and return the errno for the reply.
    pub fn log_and_errno(&self) -> c_int {
        let errno = self.error.to_errno();
        // ENOENT on lookup is normal — log at trace instead of warn.
        if errno == libc::ENOENT {
            trace!(
                op = self.operation,
                ino = self.ino,
                errno,
                error = %self.error,
                "FUSE op returned ENOENT"
            );
        } else {
            warn!(
                op = self.operation,
                ino = self.ino,
                offset = self.offset,
                errno,
                error = %self.error,
                "FUSE op failed"
            );
        }
        errno
    }
}

// ── Type conversions ────────────────────────────────────────────────────────

/// Convert an `ffs_core::FileType` to `fuser::FileType`.
fn to_fuser_file_type(ft: FfsFileType) -> FileType {
    match ft {
        FfsFileType::RegularFile => FileType::RegularFile,
        FfsFileType::Directory => FileType::Directory,
        FfsFileType::Symlink => FileType::Symlink,
        FfsFileType::BlockDevice => FileType::BlockDevice,
        FfsFileType::CharDevice => FileType::CharDevice,
        FfsFileType::Fifo => FileType::NamedPipe,
        FfsFileType::Socket => FileType::Socket,
    }
}

/// Convert an `ffs_core::InodeAttr` to `fuser::FileAttr`.
fn to_file_attr(attr: &InodeAttr) -> FileAttr {
    FileAttr {
        ino: attr.ino.0,
        size: attr.size,
        blocks: attr.blocks,
        atime: attr.atime,
        mtime: attr.mtime,
        ctime: attr.ctime,
        crtime: attr.crtime,
        kind: to_fuser_file_type(attr.kind),
        perm: attr.perm,
        nlink: attr.nlink,
        uid: attr.uid,
        gid: attr.gid,
        rdev: attr.rdev,
        blksize: attr.blksize,
        flags: 0,
    }
}

// ── Mount options ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct MountOptions {
    pub read_only: bool,
    pub allow_other: bool,
    pub auto_unmount: bool,
    /// Optional append-only trace file for recording every FUSE ioctl callback.
    ///
    /// Used by end-to-end harness tests to distinguish kernel/VFS rejections
    /// from requests that actually reached FrankenFS userspace handling.
    pub ioctl_trace_path: Option<PathBuf>,
    /// Number of worker threads for FUSE dispatch.
    ///
    /// For explicit non-zero values, FrankenFS maps this to kernel FUSE queue
    /// tuning (`max_background` and `congestion_threshold`) so mount behavior
    /// changes under load. A value of `0` means "auto" and uses defaults.
    pub worker_threads: usize,
}

impl Default for MountOptions {
    fn default() -> Self {
        Self {
            read_only: true,
            allow_other: false,
            auto_unmount: true,
            ioctl_trace_path: None,
            worker_threads: 0,
        }
    }
}

impl MountOptions {
    /// Resolved thread count.
    ///
    /// `worker_threads == 0` means "auto": `min(available_parallelism, 8)`.
    /// Non-zero values are returned as-is (clamped to at least 1).
    #[must_use]
    pub fn resolved_thread_count(&self) -> usize {
        if self.worker_threads == 0 {
            std::thread::available_parallelism()
                .map_or(1, usize::from)
                .min(8)
        } else {
            self.worker_threads.max(1)
        }
    }
}

// ── Cache-line padding ──────────────────────────────────────────────────────

/// Pad a value to 64 bytes to avoid false sharing between hot counters
/// updated on different CPU cores.
#[repr(C, align(64))]
pub struct CacheLinePadded<T>(pub T);

impl<T: std::fmt::Debug> std::fmt::Debug for CacheLinePadded<T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

// ── Atomic metrics ──────────────────────────────────────────────────────────

/// Lock-free per-mount request counters.
///
/// Each counter sits on its own cache line (64 B) so cores updating
/// different counters never invalidate each other's L1 lines.
#[repr(C)]
pub struct AtomicMetrics {
    pub requests_total: CacheLinePadded<AtomicU64>,
    pub requests_ok: CacheLinePadded<AtomicU64>,
    pub requests_err: CacheLinePadded<AtomicU64>,
    pub bytes_read: CacheLinePadded<AtomicU64>,
    /// Requests delayed by backpressure throttling.
    pub requests_throttled: CacheLinePadded<AtomicU64>,
    /// Requests rejected (shed) by backpressure.
    pub requests_shed: CacheLinePadded<AtomicU64>,
}

impl AtomicMetrics {
    #[must_use]
    pub fn new() -> Self {
        Self {
            requests_total: CacheLinePadded(AtomicU64::new(0)),
            requests_ok: CacheLinePadded(AtomicU64::new(0)),
            requests_err: CacheLinePadded(AtomicU64::new(0)),
            bytes_read: CacheLinePadded(AtomicU64::new(0)),
            requests_throttled: CacheLinePadded(AtomicU64::new(0)),
            requests_shed: CacheLinePadded(AtomicU64::new(0)),
        }
    }

    fn record_ok(&self) {
        self.requests_total.0.fetch_add(1, Ordering::Relaxed);
        self.requests_ok.0.fetch_add(1, Ordering::Relaxed);
    }

    fn record_err(&self) {
        self.requests_total.0.fetch_add(1, Ordering::Relaxed);
        self.requests_err.0.fetch_add(1, Ordering::Relaxed);
    }

    fn record_bytes_read(&self, n: u64) {
        self.bytes_read.0.fetch_add(n, Ordering::Relaxed);
    }

    fn record_throttled(&self) {
        self.requests_throttled.0.fetch_add(1, Ordering::Relaxed);
    }

    fn record_shed(&self) {
        self.requests_shed.0.fetch_add(1, Ordering::Relaxed);
    }

    /// Snapshot of all counters (for diagnostics / reporting).
    #[must_use]
    pub fn snapshot(&self) -> MetricsSnapshot {
        MetricsSnapshot {
            requests_total: self.requests_total.0.load(Ordering::Relaxed),
            requests_ok: self.requests_ok.0.load(Ordering::Relaxed),
            requests_err: self.requests_err.0.load(Ordering::Relaxed),
            bytes_read: self.bytes_read.0.load(Ordering::Relaxed),
            requests_throttled: self.requests_throttled.0.load(Ordering::Relaxed),
            requests_shed: self.requests_shed.0.load(Ordering::Relaxed),
        }
    }
}

impl Default for AtomicMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for AtomicMetrics {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = self.snapshot();
        f.debug_struct("AtomicMetrics")
            .field("requests_total", &s.requests_total)
            .field("requests_ok", &s.requests_ok)
            .field("requests_err", &s.requests_err)
            .field("bytes_read", &s.bytes_read)
            .field("requests_throttled", &s.requests_throttled)
            .field("requests_shed", &s.requests_shed)
            .finish()
    }
}

/// Point-in-time snapshot of metrics (all plain `u64`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    pub requests_total: u64,
    pub requests_ok: u64,
    pub requests_err: u64,
    pub bytes_read: u64,
    /// Requests delayed by backpressure throttling.
    pub requests_throttled: u64,
    /// Requests rejected (shed) by backpressure.
    pub requests_shed: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccessDirection {
    Forward,
    Backward,
}

#[derive(Debug, Clone, Copy)]
struct AccessPattern {
    last_offset: u64,
    last_size: u32,
    sequential_count: u32,
    direction: AccessDirection,
    last_touch: u64,
}

#[derive(Debug, Default)]
struct AccessPredictorState {
    history: BTreeMap<u64, AccessPattern>,
    lru: BTreeMap<u64, u64>,
    next_touch: u64,
}

impl AccessPredictorState {
    fn rebase_touches(&mut self) {
        if self.history.is_empty() {
            self.lru.clear();
            self.next_touch = 0;
            return;
        }

        let mut entries: Vec<(u64, u64)> = self
            .history
            .iter()
            .map(|(ino, entry)| (entry.last_touch, *ino))
            .collect();
        entries.sort_by_key(|(touch, _)| *touch);

        self.lru.clear();
        let mut next = 1_u64;
        for (_touch, ino) in entries {
            if let Some(entry) = self.history.get_mut(&ino) {
                entry.last_touch = next;
            }
            self.lru.insert(next, ino);
            next = next.saturating_add(1);
        }

        self.next_touch = next.saturating_sub(1);
    }
}

#[derive(Debug)]
struct AccessPredictor {
    state: Mutex<AccessPredictorState>,
    max_entries: usize,
}

impl Default for AccessPredictor {
    fn default() -> Self {
        Self::new(MAX_ACCESS_PREDICTOR_ENTRIES)
    }
}

impl AccessPredictor {
    fn new(max_entries: usize) -> Self {
        Self {
            state: Mutex::new(AccessPredictorState::default()),
            max_entries: max_entries.max(1),
        }
    }

    fn fetch_size(&self, ino: InodeNumber, offset: u64, requested: u32) -> u32 {
        let guard = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("AccessPredictor state lock poisoned in fetch_size, recovering");
                poisoned.into_inner()
            }
        };
        let pattern = guard.history.get(&ino.0).copied();
        drop(guard);

        let Some(pattern) = pattern else {
            return requested;
        };
        let next_forward_offset = pattern
            .last_offset
            .saturating_add(u64::from(pattern.last_size));
        let should_batch = pattern.direction == AccessDirection::Forward
            && pattern.last_size == requested
            && pattern.sequential_count >= MIN_SEQUENTIAL_READS_FOR_BATCH
            && next_forward_offset == offset;
        if should_batch {
            requested
                .saturating_mul(COALESCED_FETCH_MULTIPLIER)
                .clamp(requested, MAX_COALESCED_READ_SIZE.max(requested))
        } else {
            requested
        }
    }

    fn record_read(&self, ino: InodeNumber, offset: u64, size: u32) {
        if size == 0 {
            return;
        }
        {
            let mut guard = match self.state.lock() {
                Ok(guard) => guard,
                Err(poisoned) => {
                    warn!("AccessPredictor state lock poisoned in record_read, recovering");
                    poisoned.into_inner()
                }
            };

            if guard.next_touch == u64::MAX {
                guard.rebase_touches();
            }
            guard.next_touch = guard.next_touch.saturating_add(1);
            let touch = guard.next_touch;
            if let Some(old_touch) = guard.history.get(&ino.0).map(|old| old.last_touch) {
                guard.lru.remove(&old_touch);
            }
            guard.lru.insert(touch, ino.0);

            let entry = guard.history.entry(ino.0).or_insert(AccessPattern {
                last_offset: offset,
                last_size: size,
                sequential_count: 1,
                direction: AccessDirection::Forward,
                last_touch: touch,
            });

            let next_forward_offset = entry.last_offset.saturating_add(u64::from(entry.last_size));
            let next_backward_offset = offset.saturating_add(u64::from(size));

            if entry.last_size == size && next_forward_offset == offset {
                entry.sequential_count = entry.sequential_count.saturating_add(1);
                entry.direction = AccessDirection::Forward;
            } else if entry.last_size == size && next_backward_offset == entry.last_offset {
                entry.sequential_count = entry.sequential_count.saturating_add(1);
                entry.direction = AccessDirection::Backward;
            } else {
                entry.sequential_count = 1;
                entry.direction = AccessDirection::Forward;
            }
            entry.last_offset = offset;
            entry.last_size = size;
            entry.last_touch = touch;

            while guard.history.len() > self.max_entries {
                if let Some((_, oldest_inode)) = guard.lru.pop_first() {
                    let _ = guard.history.remove(&oldest_inode);
                } else {
                    break;
                }
            }

            drop(guard);
        }
    }

    fn invalidate_inode(&self, ino: InodeNumber) {
        let mut guard = match self.state.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("AccessPredictor state lock poisoned in invalidate, recovering");
                poisoned.into_inner()
            }
        };
        if let Some(entry) = guard.history.remove(&ino.0) {
            guard.lru.remove(&entry.last_touch);
        }
    }
}

#[derive(Debug, Default)]
struct ReadaheadState {
    map: BTreeMap<(u64, u64), Vec<u8>>,
    fifo: std::collections::VecDeque<(u64, u64)>,
}

#[derive(Debug)]
struct ReadaheadManager {
    pending: Mutex<ReadaheadState>,
    max_pending: usize,
}

impl ReadaheadManager {
    fn new(max_pending: usize) -> Self {
        Self {
            pending: Mutex::new(ReadaheadState::default()),
            max_pending: max_pending.max(1),
        }
    }

    fn remove_fifo_entry(state: &mut ReadaheadState, key: (u64, u64)) {
        state.fifo.retain(|&existing| existing != key);
    }

    fn enforce_limit(&self, state: &mut ReadaheadState) {
        while state.fifo.len() > self.max_pending {
            if let Some(key) = state.fifo.pop_front() {
                let _ = state.map.remove(&key);
            } else {
                break;
            }
        }
    }

    fn insert_locked(&self, state: &mut ReadaheadState, key: (u64, u64), data: Vec<u8>) {
        let _ = state.map.insert(key, data);
        Self::remove_fifo_entry(state, key);
        state.fifo.push_back(key);
        self.enforce_limit(state);
    }

    fn insert(&self, ino: InodeNumber, offset: u64, data: Vec<u8>) {
        if data.is_empty() {
            return;
        }
        let mut guard = match self.pending.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("ReadaheadCache pending lock poisoned in insert, recovering");
                poisoned.into_inner()
            }
        };
        let key = (ino.0, offset);
        self.insert_locked(&mut guard, key, data);
        drop(guard);
    }

    fn take(&self, ino: InodeNumber, offset: u64, requested_len: usize) -> Option<Vec<u8>> {
        if requested_len == 0 {
            return None;
        }
        let mut guard = match self.pending.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("ReadaheadCache pending lock poisoned in take, recovering");
                poisoned.into_inner()
            }
        };
        let mut cached = guard.map.remove(&(ino.0, offset))?;
        // Remove from FIFO to avoid zombies.
        Self::remove_fifo_entry(&mut guard, (ino.0, offset));

        if cached.len() <= requested_len {
            drop(guard);
            return Some(cached);
        }

        let tail = cached.split_off(requested_len);
        let consumed = u64::try_from(cached.len()).unwrap_or(u64::MAX);
        let next_offset = offset.saturating_add(consumed);
        self.insert_locked(&mut guard, (ino.0, next_offset), tail);
        drop(guard);
        Some(cached)
    }

    fn invalidate_inode(&self, ino: InodeNumber) {
        let mut guard = match self.pending.lock() {
            Ok(guard) => guard,
            Err(poisoned) => {
                warn!("ReadaheadCache pending lock poisoned in invalidate, recovering");
                poisoned.into_inner()
            }
        };
        guard.map.retain(|(cached_ino, _), _| *cached_ino != ino.0);
        guard.fifo.retain(|(cached_ino, _)| *cached_ino != ino.0);
        drop(guard);
    }
}

// ── Shared FUSE inner state ─────────────────────────────────────────────────

/// Thread-safe shared state for the FUSE backend.
///
/// All fields are `Send + Sync`:
/// - `ops` delegates to `FsOps` which is `Send + Sync` by trait bound.
/// - `metrics` uses atomic counters with cache-line padding.
/// - `thread_count` is immutable after mount.
struct FuseInner {
    ops: Arc<dyn FsOps>,
    metrics: Arc<AtomicMetrics>,
    thread_count: usize,
    read_only: bool,
    ioctl_trace: Option<IoctlTraceProbe>,
    backpressure: Option<BackpressureGate>,
    access_predictor: AccessPredictor,
    readahead: ReadaheadManager,
}

impl std::fmt::Debug for FuseInner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FuseInner")
            .field("metrics", &self.metrics)
            .field("thread_count", &self.thread_count)
            .field("read_only", &self.read_only)
            .finish_non_exhaustive()
    }
}

/// Bounded queue capacity for the ioctl trace writer.  Sized so a busy
/// dispatcher can buffer ~4k callbacks before backpressure forces drops; in
/// practice the trace is only enabled by harness tests with low ioctl volume.
const IOCTL_TRACE_CHANNEL_CAPACITY: usize = 4096;

#[derive(Debug)]
enum IoctlTraceMsg {
    Record {
        ino: u64,
        cmd: u32,
        in_len: usize,
        out_size: u32,
    },
    /// Synchronisation barrier: the writer drains all preceding `Record`
    /// messages, then signals on the supplied reply channel.  Used by tests
    /// (and any caller that needs a happens-before guarantee for an external
    /// reader of the trace file).
    #[cfg_attr(not(test), allow(dead_code))]
    Flush(SyncSender<()>),
}

/// Off-thread ioctl trace sink.
///
/// `record` enqueues onto a bounded channel and returns immediately, so the
/// FUSE dispatcher thread is never blocked on file I/O.  A dedicated writer
/// thread drains the channel and appends each event to the configured trace
/// file as a single `write(2)` syscall (no in-process buffering — the kernel
/// page cache is buffer enough for a low-volume diagnostic, and skipping a
/// user-space buffer means external readers see events as soon as the writer
/// thread is scheduled).
///
/// On backpressure (channel full) the record is dropped and `dropped_events`
/// is incremented; the count is surfaced as a `warn!` on shutdown so the
/// trace's lossiness under load is auditable.
#[derive(Debug)]
struct IoctlTraceProbe {
    path: PathBuf,
    sender: Option<SyncSender<IoctlTraceMsg>>,
    worker: Option<JoinHandle<()>>,
    dropped_events: Arc<AtomicU64>,
}

impl IoctlTraceProbe {
    fn new(path: PathBuf) -> Self {
        let (sender, receiver) = sync_channel::<IoctlTraceMsg>(IOCTL_TRACE_CHANNEL_CAPACITY);
        let worker_path = path.clone();
        let worker = thread::Builder::new()
            .name("ffs-ioctl-trace".into())
            .spawn(move || ioctl_trace_writer_loop(&worker_path, &receiver))
            .expect("spawn ioctl trace writer thread");
        Self {
            path,
            sender: Some(sender),
            worker: Some(worker),
            dropped_events: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Non-blocking enqueue.  Increments `dropped_events` if the channel is
    /// full (writer thread is behind) so the loss is observable.
    fn record(&self, ino: u64, cmd: u32, in_len: usize, out_size: u32) {
        let Some(sender) = self.sender.as_ref() else {
            return;
        };
        if sender
            .try_send(IoctlTraceMsg::Record {
                ino,
                cmd,
                in_len,
                out_size,
            })
            .is_err()
        {
            self.dropped_events.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Round-trip a `Flush` barrier through the writer thread.  When this
    /// returns, all previously enqueued `Record` messages have been written
    /// to the trace file (visible to any same-process reader).
    #[cfg_attr(not(test), allow(dead_code))]
    fn flush_sync(&self) -> std::io::Result<()> {
        let sender = self.sender.as_ref().ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "ioctl trace writer terminated",
            )
        })?;
        let (reply_tx, reply_rx) = sync_channel::<()>(1);
        sender.send(IoctlTraceMsg::Flush(reply_tx)).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "ioctl trace writer terminated",
            )
        })?;
        reply_rx.recv().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "ioctl trace writer dropped flush reply",
            )
        })
    }
}

impl Drop for IoctlTraceProbe {
    fn drop(&mut self) {
        // Drop the sender first so the writer thread observes channel close
        // and exits its `recv()` loop.
        drop(self.sender.take());
        if let Some(worker) = self.worker.take()
            && let Err(panic) = worker.join()
        {
            warn!(
                path = %self.path.display(),
                ?panic,
                "ioctl trace writer thread panicked"
            );
        }
        let dropped = self.dropped_events.load(Ordering::Relaxed);
        if dropped > 0 {
            warn!(
                path = %self.path.display(),
                dropped,
                "ioctl trace lost events to writer-thread backpressure"
            );
        }
    }
}

fn ioctl_trace_writer_loop(path: &Path, receiver: &Receiver<IoctlTraceMsg>) {
    let mut file = match std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        Ok(file) => file,
        Err(error) => {
            warn!(
                path = %path.display(),
                %error,
                "ioctl trace writer failed to open log; dropping all events"
            );
            // Drain the channel to unblock senders that may be holding
            // `try_send` slots; flush replies still complete so callers do
            // not deadlock on a missing trace file.
            for msg in receiver {
                if let IoctlTraceMsg::Flush(reply) = msg {
                    let _ = reply.send(());
                }
            }
            return;
        }
    };
    while let Ok(msg) = receiver.recv() {
        match msg {
            IoctlTraceMsg::Record {
                ino,
                cmd,
                in_len,
                out_size,
            } => {
                let line =
                    format!("ino={ino} cmd=0x{cmd:08x} in_len={in_len} out_size={out_size}\n");
                if let Err(error) = file.write_all(line.as_bytes()) {
                    warn!(path = %path.display(), %error, "ioctl trace write failed");
                }
            }
            IoctlTraceMsg::Flush(reply) => {
                let _ = reply.send(());
            }
        }
    }
}

// ── FUSE filesystem adapter ─────────────────────────────────────────────────

/// FUSE adapter that delegates all operations to a [`FsOps`] implementation.
///
/// Internally wraps all state in `Arc<FuseInner>` so it is `Send + Sync`
/// and ready for multi-threaded FUSE dispatch.  All `FsOps` calls go
/// through `self.inner.ops` (which is `Arc<dyn FsOps>`), and lock-free
/// [`AtomicMetrics`] are updated on every request.
pub struct FrankenFuse {
    inner: Arc<FuseInner>,
}

// Compile-time assertions: FrankenFuse must be Send + Sync.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    let _ = assert_send_sync::<FrankenFuse>;
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum XattrReplyPlan {
    Size(u32),
    Data,
    Error(c_int),
}

#[derive(Debug)]
enum MutationDispatchError {
    Errno(c_int),
    Operation {
        error: FfsError,
        offset: Option<u64>,
    },
}

impl FrankenFuse {
    /// Create a new FUSE adapter wrapping the given `FsOps` implementation.
    ///
    /// Uses default thread count (auto-detected).
    #[must_use]
    pub fn new(ops: Box<dyn FsOps>) -> Self {
        Self::with_options(ops, &MountOptions::default())
    }

    /// Create a new FUSE adapter with explicit mount options.
    ///
    /// The resolved `thread_count` is logged at info level.
    #[must_use]
    pub fn with_options(ops: Box<dyn FsOps>, options: &MountOptions) -> Self {
        let thread_count = options.resolved_thread_count();
        info!(thread_count, "FrankenFuse initialized");
        Self {
            inner: Arc::new(FuseInner {
                ops: Arc::from(ops),
                metrics: Arc::new(AtomicMetrics::new()),
                thread_count,
                read_only: options.read_only,
                ioctl_trace: options.ioctl_trace_path.clone().map(IoctlTraceProbe::new),
                backpressure: None,
                access_predictor: AccessPredictor::default(),
                readahead: ReadaheadManager::new(MAX_PENDING_READAHEAD_ENTRIES),
            }),
        }
    }

    /// Create a FUSE adapter with an attached backpressure gate.
    #[must_use]
    pub fn with_backpressure(
        ops: Box<dyn FsOps>,
        options: &MountOptions,
        gate: BackpressureGate,
    ) -> Self {
        let thread_count = options.resolved_thread_count();
        info!(thread_count, "FrankenFuse initialized with backpressure");
        Self {
            inner: Arc::new(FuseInner {
                ops: Arc::from(ops),
                metrics: Arc::new(AtomicMetrics::new()),
                thread_count,
                read_only: options.read_only,
                ioctl_trace: options.ioctl_trace_path.clone().map(IoctlTraceProbe::new),
                backpressure: Some(gate),
                access_predictor: AccessPredictor::default(),
                readahead: ReadaheadManager::new(MAX_PENDING_READAHEAD_ENTRIES),
            }),
        }
    }

    /// Get a reference to the shared metrics.
    #[must_use]
    pub fn metrics(&self) -> &AtomicMetrics {
        &self.inner.metrics
    }

    /// Configured thread count.
    #[must_use]
    pub fn thread_count(&self) -> usize {
        self.inner.thread_count
    }

    /// Check backpressure for an operation. Returns `true` if the operation
    /// should be rejected (shed).
    fn should_shed(&self, op: RequestOp) -> bool {
        let Some(gate) = self.inner.backpressure.as_ref() else {
            return false;
        };

        match gate.check(op) {
            BackpressureDecision::Proceed => false,
            BackpressureDecision::Throttle => {
                self.inner.metrics.record_throttled();
                trace!(
                    ?op,
                    delay_ms = BACKPRESSURE_THROTTLE_DELAY.as_millis(),
                    "backpressure: throttling request"
                );
                std::thread::sleep(BACKPRESSURE_THROTTLE_DELAY);
                false
            }
            BackpressureDecision::Shed => {
                self.inner.metrics.record_shed();
                true
            }
        }
    }

    /// Create a `Cx` for a FUSE request.
    ///
    /// In the future this could inherit deadlines or tracing spans from the
    /// fuser `Request`, but for now we use a plain request context.
    fn cx_for_request() -> Cx {
        Cx::for_request()
    }

    fn reply_error_attr(ctx: &FuseErrorContext<'_>, reply: ReplyAttr) {
        reply.error(ctx.log_and_errno());
    }

    fn reply_error_entry(ctx: &FuseErrorContext<'_>, reply: ReplyEntry) {
        reply.error(ctx.log_and_errno());
    }

    fn reply_error_data(ctx: &FuseErrorContext<'_>, reply: ReplyData) {
        reply.error(ctx.log_and_errno());
    }

    fn reply_error_dir(ctx: &FuseErrorContext<'_>, reply: ReplyDirectory) {
        reply.error(ctx.log_and_errno());
    }

    fn reply_error_xattr(ctx: &FuseErrorContext<'_>, reply: ReplyXattr) {
        reply.error(ctx.log_and_errno());
    }

    fn reply_error_empty(ctx: &FuseErrorContext<'_>, reply: ReplyEmpty) {
        reply.error(ctx.log_and_errno());
    }

    fn reply_error_write(ctx: &FuseErrorContext<'_>, reply: ReplyWrite) {
        reply.error(ctx.log_and_errno());
    }

    fn reply_error_create(ctx: &FuseErrorContext<'_>, reply: ReplyCreate) {
        reply.error(ctx.log_and_errno());
    }

    fn classify_xattr_reply(size: u32, payload_len: usize) -> XattrReplyPlan {
        match u32::try_from(payload_len) {
            Ok(payload_len_u32) if size == 0 => XattrReplyPlan::Size(payload_len_u32),
            Ok(payload_len_u32) if payload_len_u32 <= size => XattrReplyPlan::Data,
            Ok(_) => XattrReplyPlan::Error(libc::ERANGE),
            Err(_) => XattrReplyPlan::Error(libc::EOVERFLOW),
        }
    }

    fn reply_xattr_payload(size: u32, payload: &[u8], reply: ReplyXattr) {
        match Self::classify_xattr_reply(size, payload.len()) {
            XattrReplyPlan::Size(payload_len) => reply.size(payload_len),
            XattrReplyPlan::Data => reply.data(payload),
            XattrReplyPlan::Error(errno) => reply.error(errno),
        }
    }

    #[cfg(target_os = "linux")]
    const fn missing_xattr_errno() -> c_int {
        libc::ENODATA
    }

    #[cfg(not(target_os = "linux"))]
    const fn missing_xattr_errno() -> c_int {
        libc::ENOATTR
    }

    fn parse_setxattr_mode(flags: i32, position: u32) -> Result<XattrSetMode, c_int> {
        if position != 0 {
            return Err(libc::EINVAL);
        }

        let known = XATTR_FLAG_CREATE | XATTR_FLAG_REPLACE;
        if flags & !known != 0 {
            return Err(libc::EINVAL);
        }

        let create = flags & XATTR_FLAG_CREATE != 0;
        let replace = flags & XATTR_FLAG_REPLACE != 0;
        if create && replace {
            return Err(libc::EINVAL);
        }

        if create {
            Ok(XattrSetMode::Create)
        } else if replace {
            Ok(XattrSetMode::Replace)
        } else {
            Ok(XattrSetMode::Set)
        }
    }

    fn encode_xattr_names(names: &[String]) -> Vec<u8> {
        let total_len = names.iter().map(|name| name.len() + 1).sum();
        let mut bytes = Vec::with_capacity(total_len);
        for name in names {
            bytes.extend_from_slice(name.as_bytes());
            bytes.push(0);
        }
        bytes
    }

    fn parse_fiemap_request(in_data: &[u8]) -> Result<(u64, u64, u32, u32), c_int> {
        if in_data.len() < FIEMAP_HEADER_SIZE {
            return Err(libc::EINVAL);
        }

        let fm_start = u64::from_ne_bytes(
            in_data[FIEMAP_START_OFFSET..FIEMAP_START_OFFSET + 8]
                .try_into()
                .map_err(|_| libc::EINVAL)?,
        );
        let fm_length = u64::from_ne_bytes(
            in_data[FIEMAP_LENGTH_OFFSET..FIEMAP_LENGTH_OFFSET + 8]
                .try_into()
                .map_err(|_| libc::EINVAL)?,
        );
        let fm_flags = u32::from_ne_bytes(
            in_data[FIEMAP_FLAGS_OFFSET..FIEMAP_FLAGS_OFFSET + 4]
                .try_into()
                .map_err(|_| libc::EINVAL)?,
        );
        let fm_extent_count = u32::from_ne_bytes(
            in_data[FIEMAP_EXTENT_COUNT_OFFSET..FIEMAP_EXTENT_COUNT_OFFSET + 4]
                .try_into()
                .map_err(|_| libc::EINVAL)?,
        );

        Ok((fm_start, fm_length, fm_flags, fm_extent_count))
    }

    fn parse_move_ext_request(in_data: &[u8]) -> Result<(u32, u64, u64, u64), c_int> {
        if in_data.len() < MOVE_EXT_SIZE {
            return Err(libc::EINVAL);
        }

        let reserved = u32::from_ne_bytes(
            in_data[MOVE_EXT_RESERVED_OFFSET..MOVE_EXT_RESERVED_OFFSET + 4]
                .try_into()
                .map_err(|_| libc::EINVAL)?,
        );
        if reserved != 0 {
            return Err(libc::EINVAL);
        }

        let donor_fd = u32::from_ne_bytes(
            in_data[MOVE_EXT_DONOR_FD_OFFSET..MOVE_EXT_DONOR_FD_OFFSET + 4]
                .try_into()
                .map_err(|_| libc::EINVAL)?,
        );
        let orig_start = u64::from_ne_bytes(
            in_data[MOVE_EXT_ORIG_START_OFFSET..MOVE_EXT_ORIG_START_OFFSET + 8]
                .try_into()
                .map_err(|_| libc::EINVAL)?,
        );
        let donor_start = u64::from_ne_bytes(
            in_data[MOVE_EXT_DONOR_START_OFFSET..MOVE_EXT_DONOR_START_OFFSET + 8]
                .try_into()
                .map_err(|_| libc::EINVAL)?,
        );
        let len = u64::from_ne_bytes(
            in_data[MOVE_EXT_LEN_OFFSET..MOVE_EXT_LEN_OFFSET + 8]
                .try_into()
                .map_err(|_| libc::EINVAL)?,
        );

        if orig_start.checked_add(len).is_none() || donor_start.checked_add(len).is_none() {
            return Err(libc::EINVAL);
        }

        Ok((donor_fd, orig_start, donor_start, len))
    }

    fn parse_inode_flags(in_data: &[u8]) -> Result<u32, c_int> {
        if in_data.len() < std::mem::size_of::<u32>() {
            return Err(libc::EINVAL);
        }
        let mut bytes = [0_u8; std::mem::size_of::<u32>()];
        bytes.copy_from_slice(&in_data[..std::mem::size_of::<u32>()]);
        Ok(u32::from_ne_bytes(bytes))
    }

    fn clamp_fiemap_extent_count(requested: u32, out_size: u32) -> usize {
        let max_extents_by_count = usize::try_from(requested).unwrap_or(usize::MAX);
        let max_extents_by_size = if usize::try_from(out_size).unwrap_or(0) > FIEMAP_HEADER_SIZE {
            (usize::try_from(out_size).unwrap_or(0) - FIEMAP_HEADER_SIZE) / FIEMAP_EXTENT_SIZE
        } else {
            0
        };
        max_extents_by_count.min(max_extents_by_size)
    }

    fn encode_fiemap_response(
        fm_start: u64,
        fm_length: u64,
        requested_extent_count: u32,
        extents: &[FiemapExtent],
        out_size: u32,
    ) -> Vec<u8> {
        let returned_extents = extents
            .iter()
            .take(Self::clamp_fiemap_extent_count(
                requested_extent_count,
                out_size,
            ))
            .collect::<Vec<_>>();
        let mapped_count = u32::try_from(returned_extents.len()).unwrap_or(u32::MAX);

        let response_size = FIEMAP_HEADER_SIZE + returned_extents.len() * FIEMAP_EXTENT_SIZE;
        let mut response = vec![0_u8; response_size];

        response[FIEMAP_START_OFFSET..FIEMAP_START_OFFSET + 8]
            .copy_from_slice(&fm_start.to_ne_bytes());
        response[FIEMAP_LENGTH_OFFSET..FIEMAP_LENGTH_OFFSET + 8]
            .copy_from_slice(&fm_length.to_ne_bytes());
        response[FIEMAP_MAPPED_EXTENTS_OFFSET..FIEMAP_MAPPED_EXTENTS_OFFSET + 4]
            .copy_from_slice(&mapped_count.to_ne_bytes());
        response[FIEMAP_EXTENT_COUNT_OFFSET..FIEMAP_EXTENT_COUNT_OFFSET + 4]
            .copy_from_slice(&requested_extent_count.to_ne_bytes());

        for (i, ext) in returned_extents.iter().enumerate() {
            let off = FIEMAP_HEADER_SIZE + i * FIEMAP_EXTENT_SIZE;
            response[off..off + 8].copy_from_slice(&ext.logical.to_ne_bytes());
            response[off + 8..off + 16].copy_from_slice(&ext.physical.to_ne_bytes());
            response[off + 16..off + 24].copy_from_slice(&ext.length.to_ne_bytes());
            response[off + 40..off + 44].copy_from_slice(&ext.flags.to_ne_bytes());
        }

        response
    }

    fn encode_move_ext_response(
        donor_fd: u32,
        orig_start: u64,
        donor_start: u64,
        len: u64,
        moved_len: u64,
    ) -> Vec<u8> {
        let mut response = vec![0_u8; MOVE_EXT_SIZE];
        response[MOVE_EXT_DONOR_FD_OFFSET..MOVE_EXT_DONOR_FD_OFFSET + 4]
            .copy_from_slice(&donor_fd.to_ne_bytes());
        response[MOVE_EXT_ORIG_START_OFFSET..MOVE_EXT_ORIG_START_OFFSET + 8]
            .copy_from_slice(&orig_start.to_ne_bytes());
        response[MOVE_EXT_DONOR_START_OFFSET..MOVE_EXT_DONOR_START_OFFSET + 8]
            .copy_from_slice(&donor_start.to_ne_bytes());
        response[MOVE_EXT_LEN_OFFSET..MOVE_EXT_LEN_OFFSET + 8].copy_from_slice(&len.to_ne_bytes());
        response[MOVE_EXT_MOVED_LEN_OFFSET..MOVE_EXT_MOVED_LEN_OFFSET + 8]
            .copy_from_slice(&moved_len.to_ne_bytes());
        response
    }

    fn validate_move_ext_range(
        blksize: u32,
        orig_start: u64,
        donor_start: u64,
        len: u64,
    ) -> Result<(), c_int> {
        let blocks_per_page = (MOVE_EXT_PAGE_SIZE_BYTES / u64::from(blksize.max(1))).max(1);
        if orig_start % blocks_per_page != donor_start % blocks_per_page {
            return Err(libc::EINVAL);
        }

        let orig_end = orig_start.checked_add(len).ok_or(libc::EINVAL)?;
        let donor_end = donor_start.checked_add(len).ok_or(libc::EINVAL)?;
        if orig_start >= EXT4_MOVE_EXT_MAX_BLOCKS
            || donor_start >= EXT4_MOVE_EXT_MAX_BLOCKS
            || len > EXT4_MOVE_EXT_MAX_BLOCKS
            || orig_end >= EXT4_MOVE_EXT_MAX_BLOCKS
            || donor_end >= EXT4_MOVE_EXT_MAX_BLOCKS
        {
            return Err(libc::EINVAL);
        }

        Ok(())
    }

    #[allow(clippy::too_many_lines)]
    fn dispatch_ioctl(
        &self,
        ino: u64,
        fh: u64,
        cmd: u32,
        in_data: &[u8],
        out_size: u32,
    ) -> IoctlResult {
        match cmd {
            FS_IOC_FIEMAP => {
                let (fm_start, fm_length, fm_flags, fm_extent_count) =
                    match Self::parse_fiemap_request(in_data) {
                        Ok(request) => request,
                        Err(errno) => return IoctlResult::Error(errno),
                    };
                if fm_flags & !FIEMAP_SUPPORTED_FLAGS != 0 {
                    return IoctlResult::Error(libc::EBADR);
                }

                if out_size < u32::try_from(FIEMAP_HEADER_SIZE).unwrap_or(u32::MAX) {
                    return IoctlResult::Error(libc::EINVAL);
                }

                let cx = Self::cx_for_request();
                if fm_flags & FIEMAP_FLAG_SYNC != 0 && !self.inner.read_only {
                    match self.with_request_scope(&cx, RequestOp::Fsync, |cx, scope| {
                        self.inner
                            .ops
                            .fsync(cx, scope, InodeNumber(ino), fh, false)?;
                        self.inner.ops.commit_request_scope(scope)?;
                        Ok(())
                    }) {
                        Ok(()) => {}
                        Err(error) => return IoctlResult::Error(error.to_errno()),
                    }
                }
                let extents =
                    match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                        self.inner
                            .ops
                            .fiemap(cx, scope, InodeNumber(ino), fm_start, fm_length)
                    }) {
                        Ok(exts) => exts,
                        Err(error) => return IoctlResult::Error(error.to_errno()),
                    };

                IoctlResult::Data(Self::encode_fiemap_response(
                    fm_start,
                    fm_length,
                    fm_extent_count,
                    &extents,
                    out_size,
                ))
            }
            EXT4_IOC_GETFLAGS => {
                if out_size < u32::try_from(std::mem::size_of::<u32>()).unwrap_or(u32::MAX) {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner.ops.get_inode_flags(cx, scope, InodeNumber(ino))
                }) {
                    Ok(flags) => IoctlResult::Data(flags.to_ne_bytes().to_vec()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            EXT4_IOC_GETVERSION => {
                if out_size < u32::try_from(std::mem::size_of::<u32>()).unwrap_or(u32::MAX) {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlRead, |cx, scope| {
                    self.inner
                        .ops
                        .get_inode_generation(cx, scope, InodeNumber(ino))
                }) {
                    Ok(generation) => IoctlResult::Data(generation.to_ne_bytes().to_vec()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            EXT4_IOC_SETFLAGS => {
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                let flags = match Self::parse_inode_flags(in_data) {
                    Ok(flags) => flags,
                    Err(errno) => return IoctlResult::Error(errno),
                };

                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    self.inner
                        .ops
                        .set_inode_flags(cx, scope, InodeNumber(ino), flags)?;
                    self.inner.ops.commit_request_scope(scope)?;
                    Ok(())
                }) {
                    Ok(()) => IoctlResult::Data(Vec::new()),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            EXT4_IOC_MOVE_EXT => {
                if self.inner.read_only {
                    return IoctlResult::Error(libc::EROFS);
                }
                if out_size < u32::try_from(MOVE_EXT_SIZE).unwrap_or(u32::MAX) {
                    return IoctlResult::Error(libc::EINVAL);
                }
                let (donor_fd, orig_start, donor_start, len) =
                    match Self::parse_move_ext_request(in_data) {
                        Ok(request) => request,
                        Err(errno) => return IoctlResult::Error(errno),
                    };

                let cx = Self::cx_for_request();
                match self.with_request_scope(&cx, RequestOp::IoctlWrite, |cx, scope| {
                    let attr = self.inner.ops.getattr(cx, scope, InodeNumber(ino))?;
                    Self::validate_move_ext_range(attr.blksize, orig_start, donor_start, len)
                        .map_err(|_| FfsError::InvalidGeometry("invalid move_ext range".into()))?;
                    let moved_len = self.inner.ops.move_ext(
                        cx,
                        scope,
                        InodeNumber(ino),
                        donor_fd,
                        orig_start,
                        donor_start,
                        len,
                    )?;
                    self.inner.ops.commit_request_scope(scope)?;
                    Ok(moved_len)
                }) {
                    Ok(moved_len) => IoctlResult::Data(Self::encode_move_ext_response(
                        donor_fd,
                        orig_start,
                        donor_start,
                        len,
                        moved_len,
                    )),
                    Err(error) => IoctlResult::Error(error.to_errno()),
                }
            }
            _ => IoctlResult::Error(libc::ENOTTY),
        }
    }

    fn record_ioctl_probe(&self, ino: u64, cmd: u32, in_len: usize, out_size: u32) {
        let Some(trace) = self.inner.ioctl_trace.as_ref() else {
            return;
        };
        // Non-blocking enqueue onto the writer thread's bounded channel.
        // Backpressure is recorded inside the probe and surfaced on shutdown.
        trace.record(ino, cmd, in_len, out_size);
    }

    fn with_request_scope<T, F>(&self, cx: &Cx, op: RequestOp, f: F) -> ffs_error::Result<T>
    where
        F: FnOnce(&Cx, &mut RequestScope) -> ffs_error::Result<T>,
    {
        let mut scope = match self.inner.ops.begin_request_scope(cx, op) {
            Ok(scope) => scope,
            Err(e) => {
                self.inner.metrics.record_err();
                return Err(e);
            }
        };
        let op_result = f(cx, &mut scope);
        let end_result = self.inner.ops.end_request_scope(cx, op, scope);

        match (op_result, end_result) {
            (Ok(value), Ok(())) => {
                self.inner.metrics.record_ok();
                Ok(value)
            }
            (Ok(_), Err(end_err)) => {
                self.inner.metrics.record_err();
                Err(end_err)
            }
            (Err(op_err), Ok(())) => {
                self.inner.metrics.record_err();
                Err(op_err)
            }
            (Err(op_err), Err(end_err)) => {
                self.inner.metrics.record_err();
                warn!(?op, error = %end_err, "request scope cleanup failed after operation error");
                Err(op_err)
            }
        }
    }

    fn enforce_mutation_guards(
        &self,
        op: RequestOp,
        ino_for_logging: u64,
    ) -> Result<(), MutationDispatchError> {
        if self.inner.read_only {
            return Err(MutationDispatchError::Errno(libc::EROFS));
        }
        if self.should_shed(op) {
            warn!(
                ino = ino_for_logging,
                ?op,
                "backpressure: shedding mutation request"
            );
            return Err(MutationDispatchError::Errno(libc::EBUSY));
        }
        Ok(())
    }

    fn dispatch_mkdir(
        &self,
        parent: u64,
        name: &OsStr,
        mode: u16,
        uid: u32,
        gid: u32,
    ) -> Result<InodeAttr, MutationDispatchError> {
        self.enforce_mutation_guards(RequestOp::Mkdir, parent)?;
        let cx = Self::cx_for_request();
        self.with_request_scope(&cx, RequestOp::Mkdir, |cx, scope| {
            let attr =
                self.inner
                    .ops
                    .mkdir(cx, scope, InodeNumber(parent), name, mode, uid, gid)?;
            self.inner.ops.commit_request_scope(scope)?;
            Ok(attr)
        })
        .map_err(|error| MutationDispatchError::Operation {
            error,
            offset: None,
        })
    }

    fn dispatch_rmdir(&self, parent: u64, name: &OsStr) -> Result<(), MutationDispatchError> {
        self.enforce_mutation_guards(RequestOp::Rmdir, parent)?;
        let cx = Self::cx_for_request();
        self.with_request_scope(&cx, RequestOp::Rmdir, |cx, scope| {
            self.inner.ops.rmdir(cx, scope, InodeNumber(parent), name)?;
            self.inner.ops.commit_request_scope(scope)?;
            Ok(())
        })
        .map_err(|error| MutationDispatchError::Operation {
            error,
            offset: None,
        })
    }

    fn dispatch_rename(
        &self,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
    ) -> Result<(), MutationDispatchError> {
        self.enforce_mutation_guards(RequestOp::Rename, parent)?;
        let cx = Self::cx_for_request();
        self.with_request_scope(&cx, RequestOp::Rename, |cx, scope| {
            self.inner.ops.rename(
                cx,
                scope,
                InodeNumber(parent),
                name,
                InodeNumber(newparent),
                newname,
            )?;
            self.inner.ops.commit_request_scope(scope)?;
            Ok(())
        })
        .map_err(|error| MutationDispatchError::Operation {
            error,
            offset: None,
        })
    }

    fn dispatch_write(
        &self,
        ino: u64,
        offset: i64,
        data: &[u8],
    ) -> Result<u32, MutationDispatchError> {
        self.enforce_mutation_guards(RequestOp::Write, ino)?;
        let byte_offset =
            u64::try_from(offset).map_err(|_| MutationDispatchError::Errno(libc::EINVAL))?;
        let cx = Self::cx_for_request();
        let (written, _commit_seq) = self
            .with_request_scope(&cx, RequestOp::Write, |cx, scope| {
                let bytes = self
                    .inner
                    .ops
                    .write(cx, scope, InodeNumber(ino), byte_offset, data)?;
                let seq = self.inner.ops.commit_request_scope(scope)?;
                Ok((bytes, seq))
            })
            .map_err(|error| MutationDispatchError::Operation {
                error,
                offset: Some(byte_offset),
            })?;
        self.inner.readahead.invalidate_inode(InodeNumber(ino));
        // Update writeback barrier if enabled.
        Ok(written)
    }

    fn read_with_readahead(
        &self,
        cx: &Cx,
        ino: InodeNumber,
        byte_offset: u64,
        size: u32,
    ) -> ffs_error::Result<Vec<u8>> {
        let requested_len = usize::try_from(size).unwrap_or(usize::MAX);
        self.with_request_scope(cx, RequestOp::Read, |cx, scope| {
            let mut served = self
                .inner
                .readahead
                .take(ino, byte_offset, requested_len)
                .map_or_else(Vec::new, |prefetched| {
                    trace!(
                        target: "ffs::fuse::io",
                        event = "readahead_hit",
                        ino = ino.0,
                        offset = byte_offset,
                        bytes = prefetched.len()
                    );
                    prefetched
                });

            if served.len() < requested_len {
                let remaining_req =
                    size.saturating_sub(u32::try_from(served.len()).unwrap_or(u32::MAX));
                let next_offset =
                    byte_offset.saturating_add(u64::try_from(served.len()).unwrap_or(u64::MAX));
                let fetch_size =
                    self.inner
                        .access_predictor
                        .fetch_size(ino, next_offset, remaining_req);

                let mut fetched = self
                    .inner
                    .ops
                    .read(cx, scope, ino, next_offset, fetch_size)?;
                let fetched_served_len = (requested_len - served.len()).min(fetched.len());
                let tail = fetched.split_off(fetched_served_len);

                served.append(&mut fetched);

                if !tail.is_empty() {
                    let consumed = u64::try_from(fetched_served_len).unwrap_or(u64::MAX);
                    let prefetch_offset = next_offset.saturating_add(consumed);
                    let prefetch_bytes = tail.len();
                    self.inner.readahead.insert(ino, prefetch_offset, tail);
                    debug!(
                        target: "ffs::fuse::io",
                        event = "readahead_queued",
                        ino = ino.0,
                        offset = prefetch_offset,
                        bytes = prefetch_bytes
                    );
                }
            }

            self.inner.access_predictor.record_read(
                ino,
                byte_offset,
                u32::try_from(served.len()).unwrap_or(u32::MAX),
            );

            Ok(served)
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum IoctlResult {
    Data(Vec<u8>),
    Error(c_int),
}

impl Filesystem for FrankenFuse {
    fn init(&mut self, _req: &Request<'_>, _config: &mut KernelConfig) -> Result<(), c_int> {
        Ok(())
    }

    fn destroy(&mut self) {
        let cx = Self::cx_for_request();
        if let Err(e) = self.inner.ops.flush_on_destroy(&cx) {
            warn!("flush_on_destroy failed during FUSE destroy: {e}");
        }
    }

    fn forget(&mut self, _req: &Request<'_>, ino: u64, _nlookup: u64) {
        let inode = InodeNumber(ino);
        self.inner.readahead.invalidate_inode(inode);
        self.inner.access_predictor.invalidate_inode(inode);
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, _fh: Option<u64>, reply: ReplyAttr) {
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Getattr, |cx, scope| {
            self.inner.ops.getattr(cx, scope, InodeNumber(ino))
        }) {
            Ok(attr) => reply.attr(&ATTR_TTL, &to_file_attr(&attr)),
            Err(e) => {
                Self::reply_error_attr(
                    &FuseErrorContext {
                        error: &e,
                        operation: "getattr",
                        ino,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    fn statfs(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyStatfs) {
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Statfs, |cx, scope| {
            self.inner.ops.statfs(cx, scope, InodeNumber(ino))
        }) {
            Ok(stats) => reply.statfs(
                stats.blocks,
                stats.blocks_free,
                stats.blocks_available,
                stats.files,
                stats.files_free,
                stats.block_size,
                stats.name_max,
                stats.fragment_size,
            ),
            Err(e) => {
                let ctx = FuseErrorContext {
                    error: &e,
                    operation: "statfs",
                    ino,
                    offset: None,
                };
                reply.error(ctx.log_and_errno());
            }
        }
    }

    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Lookup, |cx, scope| {
            self.inner.ops.lookup(cx, scope, InodeNumber(parent), name)
        }) {
            Ok(attr) => reply.entry(&ATTR_TTL, &to_file_attr(&attr), attr.generation),
            Err(e) => {
                Self::reply_error_entry(
                    &FuseErrorContext {
                        error: &e,
                        operation: "lookup",
                        ino: parent,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    fn open(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Open, |_cx, _scope| Ok(())) {
            // Stateless open: we don't track file handles.
            Ok(()) => reply.opened(0, 0),
            Err(e) => {
                let ctx = FuseErrorContext {
                    error: &e,
                    operation: "open",
                    ino,
                    offset: None,
                };
                reply.error(ctx.log_and_errno());
            }
        }
    }

    fn opendir(&mut self, _req: &Request<'_>, ino: u64, _flags: i32, reply: ReplyOpen) {
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Opendir, |_cx, _scope| Ok(())) {
            Ok(()) => reply.opened(0, 0),
            Err(e) => {
                let ctx = FuseErrorContext {
                    error: &e,
                    operation: "opendir",
                    ino,
                    offset: None,
                };
                reply.error(ctx.log_and_errno());
            }
        }
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let cx = Self::cx_for_request();
        let Ok(byte_offset) = u64::try_from(offset) else {
            warn!(ino, offset, "read: negative offset");
            reply.error(libc::EINVAL);
            return;
        };
        match self.read_with_readahead(&cx, InodeNumber(ino), byte_offset, size) {
            Ok(data) => {
                self.inner
                    .metrics
                    .record_bytes_read(u64::try_from(data.len()).unwrap_or(u64::MAX));
                reply.data(&data);
            }
            Err(e) => {
                Self::reply_error_data(
                    &FuseErrorContext {
                        error: &e,
                        operation: "read",
                        ino,
                        offset: Some(byte_offset),
                    },
                    reply,
                );
            }
        }
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        mut reply: ReplyDirectory,
    ) {
        let cx = Self::cx_for_request();
        let Ok(fs_offset) = u64::try_from(offset) else {
            warn!(ino, offset, "readdir: negative offset");
            reply.error(libc::EINVAL);
            return;
        };
        match self.with_request_scope(&cx, RequestOp::Readdir, |cx, scope| {
            self.inner
                .ops
                .readdir(cx, scope, InodeNumber(ino), fs_offset)
        }) {
            Ok(entries) => {
                for entry in &entries {
                    #[cfg(unix)]
                    let name = OsStr::from_bytes(&entry.name);
                    #[cfg(not(unix))]
                    let owned_name = entry.name_str();
                    #[cfg(not(unix))]
                    let name = OsStr::new(&owned_name);

                    let full = reply.add(
                        entry.ino.0,
                        i64::try_from(entry.offset).unwrap_or(i64::MAX),
                        to_fuser_file_type(entry.kind),
                        name,
                    );
                    if full {
                        break;
                    }
                }
                reply.ok();
            }
            Err(e) => {
                Self::reply_error_dir(
                    &FuseErrorContext {
                        error: &e,
                        operation: "readdir",
                        ino,
                        offset: Some(fs_offset),
                    },
                    reply,
                );
            }
        }
    }

    fn readlink(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyData) {
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Readlink, |cx, scope| {
            self.inner.ops.readlink(cx, scope, InodeNumber(ino))
        }) {
            Ok(target) => reply.data(&target),
            Err(e) => {
                Self::reply_error_data(
                    &FuseErrorContext {
                        error: &e,
                        operation: "readlink",
                        ino,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    fn symlink(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        link: &Path,
        reply: ReplyEntry,
    ) {
        if self.inner.read_only {
            reply.error(libc::EROFS);
            return;
        }
        if self.should_shed(RequestOp::Symlink) {
            warn!(parent, "backpressure: shedding symlink");
            reply.error(libc::EBUSY);
            return;
        }
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Symlink, |cx, scope| {
            let attr = self.inner.ops.symlink(
                cx,
                scope,
                InodeNumber(parent),
                name,
                link,
                req.uid(),
                req.gid(),
            )?;
            self.inner.ops.commit_request_scope(scope)?;
            Ok(attr)
        }) {
            Ok(attr) => reply.entry(&ATTR_TTL, &to_file_attr(&attr), attr.generation),
            Err(e) => {
                Self::reply_error_entry(
                    &FuseErrorContext {
                        error: &e,
                        operation: "symlink",
                        ino: parent,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    fn getxattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        name: &OsStr,
        size: u32,
        reply: ReplyXattr,
    ) {
        let Some(name) = name.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Getxattr, |cx, _scope| {
            self.inner.ops.getxattr(cx, InodeNumber(ino), name)
        }) {
            Ok(Some(value)) => Self::reply_xattr_payload(size, &value, reply),
            Ok(None) => reply.error(Self::missing_xattr_errno()),
            Err(e) => {
                Self::reply_error_xattr(
                    &FuseErrorContext {
                        error: &e,
                        operation: "getxattr",
                        ino,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    fn setxattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        name: &OsStr,
        value: &[u8],
        flags: i32,
        position: u32,
        reply: ReplyEmpty,
    ) {
        if self.inner.read_only {
            reply.error(libc::EROFS);
            return;
        }
        if self.should_shed(RequestOp::Setxattr) {
            warn!(ino, "backpressure: shedding setxattr");
            reply.error(libc::EBUSY);
            return;
        }
        let Some(name) = name.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };
        let Ok(mode) = Self::parse_setxattr_mode(flags, position) else {
            reply.error(libc::EINVAL);
            return;
        };

        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Setxattr, |cx, scope| {
            self.inner
                .ops
                .setxattr(cx, scope, InodeNumber(ino), name, value, mode)?;
            self.inner.ops.commit_request_scope(scope)?;
            Ok(())
        }) {
            Ok(()) => reply.ok(),
            Err(e) => {
                if matches!(mode, XattrSetMode::Replace)
                    && matches!(e, FfsError::NotFound(_))
                    && self
                        .inner
                        .ops
                        .getattr(&cx, &mut RequestScope::empty(), InodeNumber(ino))
                        .is_ok()
                {
                    reply.error(Self::missing_xattr_errno());
                    return;
                }
                Self::reply_error_empty(
                    &FuseErrorContext {
                        error: &e,
                        operation: "setxattr",
                        ino,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    fn removexattr(&mut self, _req: &Request<'_>, ino: u64, name: &OsStr, reply: ReplyEmpty) {
        if self.inner.read_only {
            reply.error(libc::EROFS);
            return;
        }
        if self.should_shed(RequestOp::Removexattr) {
            warn!(ino, "backpressure: shedding removexattr");
            reply.error(libc::EBUSY);
            return;
        }
        let Some(name) = name.to_str() else {
            reply.error(libc::EINVAL);
            return;
        };

        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Removexattr, |cx, scope| {
            let removed = self
                .inner
                .ops
                .removexattr(cx, scope, InodeNumber(ino), name)?;
            self.inner.ops.commit_request_scope(scope)?;
            Ok(removed)
        }) {
            Ok(true) => reply.ok(),
            Ok(false) => reply.error(Self::missing_xattr_errno()),
            Err(e) => {
                Self::reply_error_empty(
                    &FuseErrorContext {
                        error: &e,
                        operation: "removexattr",
                        ino,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    fn listxattr(&mut self, _req: &Request<'_>, ino: u64, size: u32, reply: ReplyXattr) {
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Listxattr, |cx, _scope| {
            self.inner.ops.listxattr(cx, InodeNumber(ino))
        }) {
            Ok(names) => {
                let payload = Self::encode_xattr_names(&names);
                Self::reply_xattr_payload(size, &payload, reply);
            }
            Err(e) => {
                Self::reply_error_xattr(
                    &FuseErrorContext {
                        error: &e,
                        operation: "listxattr",
                        ino,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    // ── Write operations ─────────────────────────────────────────────────

    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        _ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        if self.inner.read_only {
            reply.error(libc::EROFS);
            return;
        }
        if self.should_shed(RequestOp::Setattr) {
            warn!(ino, "backpressure: shedding setattr");
            reply.error(libc::EBUSY);
            return;
        }
        let cx = Self::cx_for_request();
        let resolve_time = |t: TimeOrNow| -> SystemTime {
            match t {
                TimeOrNow::SpecificTime(st) => st,
                TimeOrNow::Now => SystemTime::now(),
            }
        };
        let attrs = SetAttrRequest {
            #[allow(clippy::cast_possible_truncation)]
            mode: mode.map(|m| m as u16), // FUSE mode is u32, ext4 mode is u16
            uid,
            gid,
            size,
            atime: atime.map(resolve_time),
            mtime: mtime.map(resolve_time),
        };
        match self.with_request_scope(&cx, RequestOp::Setattr, |cx, scope| {
            let attr = self
                .inner
                .ops
                .setattr(cx, scope, InodeNumber(ino), &attrs)?;
            self.inner.ops.commit_request_scope(scope)?;
            Ok(attr)
        }) {
            Ok(attr) => reply.attr(&ATTR_TTL, &to_file_attr(&attr)),
            Err(e) => {
                Self::reply_error_attr(
                    &FuseErrorContext {
                        error: &e,
                        operation: "setattr",
                        ino,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    #[allow(clippy::cast_possible_truncation)] // FUSE mode u32 → ext4 u16
    fn mkdir(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        match self.dispatch_mkdir(parent, name, mode as u16, req.uid(), req.gid()) {
            Ok(attr) => reply.entry(&ATTR_TTL, &to_file_attr(&attr), attr.generation),
            Err(MutationDispatchError::Errno(errno)) => reply.error(errno),
            Err(MutationDispatchError::Operation { error, offset }) => {
                Self::reply_error_entry(
                    &FuseErrorContext {
                        error: &error,
                        operation: "mkdir",
                        ino: parent,
                        offset,
                    },
                    reply,
                );
            }
        }
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        if self.inner.read_only {
            reply.error(libc::EROFS);
            return;
        }
        if self.should_shed(RequestOp::Unlink) {
            warn!(parent, "backpressure: shedding unlink");
            reply.error(libc::EBUSY);
            return;
        }
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Unlink, |cx, scope| {
            self.inner
                .ops
                .unlink(cx, scope, InodeNumber(parent), name)?;
            self.inner.ops.commit_request_scope(scope)?;
            Ok(())
        }) {
            Ok(()) => reply.ok(),
            Err(e) => {
                Self::reply_error_empty(
                    &FuseErrorContext {
                        error: &e,
                        operation: "unlink",
                        ino: parent,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        match self.dispatch_rmdir(parent, name) {
            Ok(()) => reply.ok(),
            Err(MutationDispatchError::Errno(errno)) => reply.error(errno),
            Err(MutationDispatchError::Operation { error, offset }) => {
                Self::reply_error_empty(
                    &FuseErrorContext {
                        error: &error,
                        operation: "rmdir",
                        ino: parent,
                        offset,
                    },
                    reply,
                );
            }
        }
    }

    fn rename(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        flags: u32,
        reply: ReplyEmpty,
    ) {
        if flags != 0 {
            // RENAME_NOREPLACE, RENAME_EXCHANGE, etc. are not currently supported.
            // Silently ignoring them would violate POSIX semantics (e.g., overwriting
            // a file when NOREPLACE was explicitly requested).
            reply.error(libc::EINVAL);
            return;
        }

        match self.dispatch_rename(parent, name, newparent, newname) {
            Ok(()) => reply.ok(),
            Err(MutationDispatchError::Errno(errno)) => reply.error(errno),
            Err(MutationDispatchError::Operation { error, offset }) => {
                Self::reply_error_empty(
                    &FuseErrorContext {
                        error: &error,
                        operation: "rename",
                        ino: parent,
                        offset,
                    },
                    reply,
                );
            }
        }
    }

    fn link(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        newparent: u64,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        if self.inner.read_only {
            reply.error(libc::EROFS);
            return;
        }
        if self.should_shed(RequestOp::Link) {
            warn!(ino, "backpressure: shedding link");
            reply.error(libc::EBUSY);
            return;
        }
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Link, |cx, scope| {
            let attr = self.inner.ops.link(
                cx,
                scope,
                InodeNumber(ino),
                InodeNumber(newparent),
                newname,
            )?;
            self.inner.ops.commit_request_scope(scope)?;
            Ok(attr)
        }) {
            Ok(attr) => reply.entry(&ATTR_TTL, &to_file_attr(&attr), attr.generation),
            Err(e) => {
                Self::reply_error_entry(
                    &FuseErrorContext {
                        error: &e,
                        operation: "link",
                        ino,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        trace!(ino, offset, len = data.len(), "FUSE write");
        match self.dispatch_write(ino, offset, data) {
            Ok(written) => reply.written(written),
            Err(MutationDispatchError::Errno(errno)) => reply.error(errno),
            Err(MutationDispatchError::Operation { error, offset }) => {
                Self::reply_error_write(
                    &FuseErrorContext {
                        error: &error,
                        operation: "write",
                        ino,
                        offset,
                    },
                    reply,
                );
            }
        }
    }

    fn fallocate(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        length: i64,
        mode: i32,
        reply: ReplyEmpty,
    ) {
        if self.inner.read_only {
            reply.error(libc::EROFS);
            return;
        }
        if self.should_shed(RequestOp::Fallocate) {
            warn!(ino, "backpressure: shedding fallocate");
            reply.error(libc::EBUSY);
            return;
        }

        let Ok(byte_offset) = u64::try_from(offset) else {
            reply.error(libc::EINVAL);
            return;
        };
        let Ok(byte_length) = u64::try_from(length) else {
            reply.error(libc::EINVAL);
            return;
        };
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Fallocate, |cx, scope| {
            self.inner.ops.fallocate(
                cx,
                scope,
                InodeNumber(ino),
                byte_offset,
                byte_length,
                mode,
            )?;
            self.inner.ops.commit_request_scope(scope)?;
            Ok(())
        }) {
            Ok(()) => reply.ok(),
            Err(e) => {
                Self::reply_error_empty(
                    &FuseErrorContext {
                        error: &e,
                        operation: "fallocate",
                        ino,
                        offset: Some(byte_offset),
                    },
                    reply,
                );
            }
        }
    }

    fn ioctl(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        _flags: u32,
        cmd: u32,
        in_data: &[u8],
        out_size: u32,
        reply: ReplyIoctl,
    ) {
        self.record_ioctl_probe(ino, cmd, in_data.len(), out_size);
        match self.dispatch_ioctl(ino, fh, cmd, in_data, out_size) {
            IoctlResult::Data(data) => reply.ioctl(0, &data),
            IoctlResult::Error(errno) => {
                if errno == libc::ENOTTY {
                    debug!(ino, cmd, "ioctl: unsupported command");
                }
                reply.error(errno);
            }
        }
    }

    fn lseek(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        whence: i32,
        reply: ReplyLseek,
    ) {
        // SEEK_SET/CUR/END are handled by the kernel; only SEEK_DATA/SEEK_HOLE
        // reach this handler.
        let Some(seek_whence) = SeekWhence::from_raw(whence) else {
            debug!(ino, whence, "lseek: unsupported whence");
            reply.error(libc::EINVAL);
            return;
        };

        // Convert offset to u64 (SEEK_DATA/SEEK_HOLE require non-negative offset).
        let Ok(offset_u64) = u64::try_from(offset) else {
            reply.error(libc::EINVAL);
            return;
        };

        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Lseek, |cx, scope| {
            self.inner
                .ops
                .lseek(cx, scope, InodeNumber(ino), offset_u64, seek_whence)
        }) {
            Ok(new_offset) => {
                // ReplyLseek::offset expects i64.
                match i64::try_from(new_offset) {
                    Ok(v) => reply.offset(v),
                    Err(_) => reply.error(libc::EOVERFLOW),
                }
            }
            Err(e) => {
                // For SEEK_DATA/SEEK_HOLE, Format errors with "ENXIO" message map to ENXIO.
                // This handles "offset >= file_size" and "no data/hole found" cases.
                let errno = if let FfsError::Format(msg) = &e {
                    if msg.contains("ENXIO") {
                        libc::ENXIO
                    } else {
                        e.to_errno()
                    }
                } else {
                    e.to_errno()
                };
                trace!(ino, offset, whence, errno, "lseek failed");
                reply.error(errno);
            }
        }
    }

    fn flush(&mut self, _req: &Request<'_>, ino: u64, fh: u64, lock_owner: u64, reply: ReplyEmpty) {
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Flush, |cx, scope| {
            self.inner
                .ops
                .flush(cx, scope, InodeNumber(ino), fh, lock_owner)
        }) {
            Ok(()) => reply.ok(),
            Err(e) => {
                Self::reply_error_empty(
                    &FuseErrorContext {
                        error: &e,
                        operation: "flush",
                        ino,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    fn fsync(&mut self, _req: &Request<'_>, ino: u64, fh: u64, datasync: bool, reply: ReplyEmpty) {
        if self.inner.read_only {
            reply.error(libc::EROFS);
            return;
        }
        if self.should_shed(RequestOp::Fsync) {
            warn!(ino, "backpressure: shedding fsync");
            reply.error(libc::EBUSY);
            return;
        }
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Fsync, |cx, scope| {
            self.inner
                .ops
                .fsync(cx, scope, InodeNumber(ino), fh, datasync)?;
            self.inner.ops.commit_request_scope(scope)?;
            Ok(())
        }) {
            Ok(()) => reply.ok(),
            Err(e) => {
                Self::reply_error_empty(
                    &FuseErrorContext {
                        error: &e,
                        operation: "fsync",
                        ino,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    fn fsyncdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        fh: u64,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        if self.inner.read_only {
            reply.error(libc::EROFS);
            return;
        }
        if self.should_shed(RequestOp::Fsyncdir) {
            warn!(ino, "backpressure: shedding fsyncdir");
            reply.error(libc::EBUSY);
            return;
        }
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Fsyncdir, |cx, scope| {
            self.inner
                .ops
                .fsyncdir(cx, scope, InodeNumber(ino), fh, datasync)?;
            self.inner.ops.commit_request_scope(scope)?;
            Ok(())
        }) {
            Ok(()) => reply.ok(),
            Err(e) => {
                Self::reply_error_empty(
                    &FuseErrorContext {
                        error: &e,
                        operation: "fsyncdir",
                        ino,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }

    #[allow(clippy::cast_possible_truncation)] // FUSE mode u32 → ext4 u16
    fn create(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        if self.inner.read_only {
            reply.error(libc::EROFS);
            return;
        }
        if self.should_shed(RequestOp::Create) {
            warn!(parent, "backpressure: shedding create");
            reply.error(libc::EBUSY);
            return;
        }
        let cx = Self::cx_for_request();
        match self.with_request_scope(&cx, RequestOp::Create, |cx, scope| {
            let attr = self.inner.ops.create(
                cx,
                scope,
                InodeNumber(parent),
                name,
                mode as u16,
                req.uid(),
                req.gid(),
            )?;
            self.inner.ops.commit_request_scope(scope)?;
            Ok(attr)
        }) {
            Ok(attr) => {
                reply.created(&ATTR_TTL, &to_file_attr(&attr), attr.generation, 0, 0);
            }
            Err(e) => {
                Self::reply_error_create(
                    &FuseErrorContext {
                        error: &e,
                        operation: "create",
                        ino: parent,
                        offset: None,
                    },
                    reply,
                );
            }
        }
    }
}

// ── Mount entrypoint ────────────────────────────────────────────────────────

/// Build a list of `fuser::MountOption` from our `MountOptions`.
fn build_mount_options(options: &MountOptions) -> Vec<MountOption> {
    let mut opts = vec![
        MountOption::FSName("frankenfs".to_owned()),
        MountOption::Subtype("ffs".to_owned()),
        MountOption::DefaultPermissions,
        MountOption::NoAtime,
    ];

    if options.read_only {
        opts.push(MountOption::RO);
    }
    if options.allow_other {
        opts.push(MountOption::AllowOther);
    }
    if options.auto_unmount {
        opts.push(MountOption::AutoUnmount);
    }
    if options.worker_threads > 0 {
        let max_background = options.resolved_thread_count();
        let congestion_threshold = max_background.saturating_mul(3).saturating_div(4).max(1);
        opts.push(MountOption::CUSTOM(format!(
            "max_background={max_background}"
        )));
        opts.push(MountOption::CUSTOM(format!(
            "congestion_threshold={congestion_threshold}"
        )));
    }

    opts
}

fn validate_mountpoint(mountpoint: &Path) -> Result<(), FuseError> {
    if mountpoint.as_os_str().is_empty() {
        return Err(FuseError::InvalidMountpoint(
            "mountpoint cannot be empty".to_owned(),
        ));
    }
    if !mountpoint.exists() {
        return Err(FuseError::InvalidMountpoint(format!(
            "mountpoint does not exist: {}",
            mountpoint.display()
        )));
    }
    if !mountpoint.is_dir() {
        return Err(FuseError::InvalidMountpoint(format!(
            "mountpoint is not a directory: {}",
            mountpoint.display()
        )));
    }
    Ok(())
}

/// Mount a FrankenFS filesystem at the given mountpoint (blocking).
///
/// This function blocks until the filesystem is unmounted.
pub fn mount(
    ops: Box<dyn FsOps>,
    mountpoint: impl AsRef<Path>,
    options: &MountOptions,
) -> Result<(), FuseError> {
    let mountpoint = mountpoint.as_ref();
    validate_mountpoint(mountpoint)?;
    let fuse_opts = build_mount_options(options);
    let fs = FrankenFuse::with_options(ops, options);
    fuser::mount2(fs, mountpoint, &fuse_opts)?;
    Ok(())
}

/// Mount a FrankenFS filesystem in the background, returning a session handle.
///
/// The filesystem is unmounted when the returned `BackgroundSession` is dropped.
pub fn mount_background(
    ops: Box<dyn FsOps>,
    mountpoint: impl AsRef<Path>,
    options: &MountOptions,
) -> Result<fuser::BackgroundSession, FuseError> {
    let mountpoint = mountpoint.as_ref();
    validate_mountpoint(mountpoint)?;
    let fuse_opts = build_mount_options(options);
    let fs = FrankenFuse::with_options(ops, options);
    let session = fuser::spawn_mount2(fs, mountpoint, &fuse_opts)?;
    Ok(session)
}

// ── Mount lifecycle ─────────────────────────────────────────────────────────

/// Configuration for a managed mount with lifecycle control.
#[derive(Debug, Clone)]
pub struct MountConfig {
    /// Base mount options (RO, allow_other, threads, etc.).
    pub options: MountOptions,
    /// Grace period for in-flight requests during unmount.
    pub unmount_timeout: Duration,
}

impl Default for MountConfig {
    fn default() -> Self {
        Self {
            options: MountOptions::default(),
            unmount_timeout: Duration::from_secs(30),
        }
    }
}

/// Handle for a live FUSE mount with lifecycle control.
///
/// Dropping the handle triggers a clean unmount.  Call [`wait`] to block
/// until external shutdown (Ctrl+C / programmatic `shutdown()`).
///
/// # Signal Handling
///
/// `MountHandle` exposes a shared `shutdown` flag (`Arc<AtomicBool>`).
/// The CLI (or any owner) should wire SIGTERM / SIGINT handlers that set
/// this flag.  [`wait`] polls the flag and triggers unmount when set.
/// The `AutoUnmount` fuser option provides a safety net: the kernel
/// unmounts the filesystem if the process exits without a clean unmount.
pub struct MountHandle {
    session: Option<fuser::BackgroundSession>,
    mountpoint: PathBuf,
    shutdown: Arc<std::sync::atomic::AtomicBool>,
    metrics: Arc<AtomicMetrics>,
    config: MountConfig,
}

impl MountHandle {
    /// The mountpoint path.
    #[must_use]
    pub fn mountpoint(&self) -> &Path {
        &self.mountpoint
    }

    /// Shared shutdown flag.
    ///
    /// Set this to `true` (from a signal handler or another thread) to
    /// trigger a graceful unmount.
    #[must_use]
    pub fn shutdown_flag(&self) -> &Arc<std::sync::atomic::AtomicBool> {
        &self.shutdown
    }

    /// Get a snapshot of the mount metrics.
    #[must_use]
    pub fn metrics_snapshot(&self) -> MetricsSnapshot {
        self.metrics.snapshot()
    }

    /// Block until the shutdown flag is set, then unmount cleanly.
    ///
    /// Returns the final metrics snapshot.
    #[must_use]
    pub fn wait(mut self) -> MetricsSnapshot {
        info!(mountpoint = %self.mountpoint.display(), "waiting for shutdown signal");
        loop {
            if self.shutdown.load(std::sync::atomic::Ordering::Relaxed) {
                info!(
                    mountpoint = %self.mountpoint.display(),
                    "shutdown signal received"
                );
                break;
            }
            if let Some(session) = self.session.as_ref() {
                if session.guard.is_finished() {
                    warn!(
                        mountpoint = %self.mountpoint.display(),
                        "fuse background session ended without explicit shutdown"
                    );
                    break;
                }
            }
            std::thread::sleep(Duration::from_millis(100));
        }
        self.do_unmount()
    }

    /// Trigger a graceful unmount.
    ///
    /// Returns the final metrics snapshot.
    #[must_use]
    pub fn unmount(mut self) -> MetricsSnapshot {
        self.do_unmount()
    }

    fn do_unmount(&mut self) -> MetricsSnapshot {
        let snap = self.metrics.snapshot();
        if let Some(session) = self.session.take() {
            info!(
                mountpoint = %self.mountpoint.display(),
                requests_total = snap.requests_total,
                requests_ok = snap.requests_ok,
                requests_err = snap.requests_err,
                bytes_read = snap.bytes_read,
                requests_throttled = snap.requests_throttled,
                requests_shed = snap.requests_shed,
                "unmounting FUSE filesystem"
            );

            let timeout = self.config.unmount_timeout;
            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                drop(session);
                let _ = tx.send(());
            });

            if rx.recv_timeout(timeout).is_err() {
                warn!("unmount timed out after {:?}", timeout);
            } else {
                info!(mountpoint = %self.mountpoint.display(), "unmount complete");
            }
        }
        snap
    }
}

impl Drop for MountHandle {
    fn drop(&mut self) {
        if self.session.is_some() {
            self.do_unmount();
        }
    }
}

impl std::fmt::Debug for MountHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MountHandle")
            .field("mountpoint", &self.mountpoint)
            .field("active", &self.session.is_some())
            .field(
                "shutdown",
                &self.shutdown.load(std::sync::atomic::Ordering::Relaxed),
            )
            .field("metrics", &self.metrics.snapshot())
            .field("unmount_timeout", &self.config.unmount_timeout)
            .finish()
    }
}

/// Mount a FrankenFS filesystem with full lifecycle control.
///
/// Returns a [`MountHandle`] that can be used to wait for signals,
/// query metrics, and trigger a clean unmount.
///
/// # Example
/// ```no_run
/// # use ffs_fuse::{MountConfig, mount_managed};
/// # fn example(ops: Box<dyn ffs_core::FsOps>) {
/// let handle = mount_managed(ops, "/mnt/ffs", &MountConfig::default()).unwrap();
/// // Wire Ctrl+C to the shutdown flag (e.g. via ctrlc crate):
/// let flag = handle.shutdown_flag().clone();
/// // ... register signal handler that sets `flag.store(true, ...)` ...
/// let stats = handle.wait();
/// println!("served {} requests", stats.requests_total);
/// # }
/// ```
pub fn mount_managed(
    ops: Box<dyn FsOps>,
    mountpoint: impl AsRef<Path>,
    config: &MountConfig,
) -> Result<MountHandle, FuseError> {
    let mountpoint = mountpoint.as_ref();
    validate_mountpoint(mountpoint)?;

    let thread_count = config.options.resolved_thread_count();
    info!(
        mountpoint = %mountpoint.display(),
        thread_count,
        read_only = config.options.read_only,
        unmount_timeout_secs = config.unmount_timeout.as_secs(),
        "mounting FrankenFS"
    );

    let fuse_opts = build_mount_options(&config.options);
    let fs = FrankenFuse::with_options(ops, &config.options);
    let metrics_ref = Arc::clone(&fs.inner.metrics);

    let session = fuser::spawn_mount2(fs, mountpoint, &fuse_opts)?;

    info!(mountpoint = %mountpoint.display(), "FUSE mount active");

    Ok(MountHandle {
        session: Some(session),
        mountpoint: mountpoint.to_owned(),
        shutdown: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        metrics: metrics_ref,
        config: config.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use ffs_core::{
        DirEntry as FfsDirEntry, FIEMAP_EXTENT_LAST, FIEMAP_EXTENT_UNWRITTEN, RequestScope,
    };
    use ffs_types::CommitSeq;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Mutex};
    use std::time::{Instant, SystemTime};

    /// Minimal FsOps stub for tests that don't need real filesystem behavior.
    struct StubFs;
    impl FsOps for StubFs {
        fn getattr(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
        ) -> ffs_error::Result<InodeAttr> {
            Err(FfsError::NotFound("stub".into()))
        }
        fn lookup(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _parent: InodeNumber,
            _name: &OsStr,
        ) -> ffs_error::Result<InodeAttr> {
            Err(FfsError::NotFound("stub".into()))
        }
        fn readdir(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
            _offset: u64,
        ) -> ffs_error::Result<Vec<FfsDirEntry>> {
            Ok(vec![])
        }
        fn read(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
            _offset: u64,
            _size: u32,
        ) -> ffs_error::Result<Vec<u8>> {
            Ok(vec![])
        }
        fn readlink(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
        ) -> ffs_error::Result<Vec<u8>> {
            Ok(vec![])
        }
    }

    fn existing_file_mountpoint() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml")
    }

    #[test]
    fn file_type_conversion_roundtrip() {
        let cases = [
            (FfsFileType::RegularFile, FileType::RegularFile),
            (FfsFileType::Directory, FileType::Directory),
            (FfsFileType::Symlink, FileType::Symlink),
            (FfsFileType::BlockDevice, FileType::BlockDevice),
            (FfsFileType::CharDevice, FileType::CharDevice),
            (FfsFileType::Fifo, FileType::NamedPipe),
            (FfsFileType::Socket, FileType::Socket),
        ];
        for (ffs_ft, expected_fuser_ft) in &cases {
            assert_eq!(to_fuser_file_type(*ffs_ft), *expected_fuser_ft);
        }
    }

    #[test]
    fn inode_attr_to_file_attr_conversion() {
        let iattr = InodeAttr {
            ino: InodeNumber(42),
            size: 1024,
            blocks: 2,
            atime: SystemTime::UNIX_EPOCH,
            mtime: SystemTime::UNIX_EPOCH,
            ctime: SystemTime::UNIX_EPOCH,
            crtime: SystemTime::UNIX_EPOCH,
            kind: FfsFileType::RegularFile,
            perm: 0o644,
            nlink: 1,
            uid: 1000,
            gid: 1000,
            rdev: 0,
            blksize: 4096,
            generation: 7,
        };
        let fattr = to_file_attr(&iattr);
        assert_eq!(fattr.ino, 42);
        assert_eq!(fattr.size, 1024);
        assert_eq!(fattr.blocks, 2);
        assert_eq!(fattr.kind, FileType::RegularFile);
        assert_eq!(fattr.perm, 0o644);
        assert_eq!(fattr.nlink, 1);
        assert_eq!(fattr.uid, 1000);
        assert_eq!(fattr.gid, 1000);
        assert_eq!(fattr.rdev, 0);
        assert_eq!(fattr.blksize, 4096);
        assert_eq!(fattr.flags, 0);
    }

    #[test]
    fn mount_options_default_is_read_only() {
        let opts = MountOptions::default();
        assert!(opts.read_only);
        assert!(!opts.allow_other);
        assert!(opts.auto_unmount);
        assert!(opts.ioctl_trace_path.is_none());
    }

    #[test]
    fn build_mount_options_includes_ro_when_read_only() {
        let opts = MountOptions::default();
        let mount_opts = build_mount_options(&opts);
        // Default includes FSName + Subtype + DefaultPermissions + NoAtime + RO + AutoUnmount = 6
        assert!(mount_opts.len() >= 5);
    }

    #[test]
    fn mount_rejects_empty_mountpoint() {
        // We can't construct a real FsOps without a filesystem, but we can
        // verify the mountpoint validation fires before any FsOps call.
        // Use a minimal stub.
        struct NeverCalledFs;
        impl FsOps for NeverCalledFs {
            fn getattr(
                &self,
                _cx: &Cx,
                _scope: &mut RequestScope,
                _ino: InodeNumber,
            ) -> ffs_error::Result<InodeAttr> {
                unreachable!()
            }
            fn lookup(
                &self,
                _cx: &Cx,
                _scope: &mut RequestScope,
                _parent: InodeNumber,
                _name: &OsStr,
            ) -> ffs_error::Result<InodeAttr> {
                unreachable!()
            }
            fn readdir(
                &self,
                _cx: &Cx,
                _scope: &mut RequestScope,
                _ino: InodeNumber,
                _offset: u64,
            ) -> ffs_error::Result<Vec<FfsDirEntry>> {
                unreachable!()
            }
            fn read(
                &self,
                _cx: &Cx,
                _scope: &mut RequestScope,
                _ino: InodeNumber,
                _offset: u64,
                _size: u32,
            ) -> ffs_error::Result<Vec<u8>> {
                unreachable!()
            }
            fn readlink(
                &self,
                _cx: &Cx,
                _scope: &mut RequestScope,
                _ino: InodeNumber,
            ) -> ffs_error::Result<Vec<u8>> {
                unreachable!()
            }
        }
        let err = mount(Box::new(NeverCalledFs), "", &MountOptions::default()).unwrap_err();
        assert!(err.to_string().contains("empty"));
    }

    #[test]
    fn mount_rejects_nonexistent_mountpoint() {
        let ops: Box<dyn FsOps> = Box::new(StubFs);
        let err = mount(
            ops,
            "/tmp/frankenfs_no_such_dir_xyzzy",
            &MountOptions::default(),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("does not exist"),
            "expected 'does not exist' in error: {err}"
        );
    }

    #[test]
    fn mount_background_rejects_nonexistent_mountpoint() {
        let ops: Box<dyn FsOps> = Box::new(StubFs);
        let err = mount_background(
            ops,
            "/tmp/frankenfs_no_such_dir_xyzzy",
            &MountOptions::default(),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("does not exist"),
            "expected 'does not exist' in error: {err}"
        );
    }

    #[test]
    fn mount_rejects_file_mountpoint() {
        let file_path = existing_file_mountpoint();
        let ops: Box<dyn FsOps> = Box::new(StubFs);
        let err = mount(ops, &file_path, &MountOptions::default()).unwrap_err();
        let err_text = err.to_string();
        assert!(
            err_text.contains("not a directory"),
            "expected 'not a directory' in error: {err_text}"
        );
    }

    #[test]
    fn mount_background_rejects_file_mountpoint() {
        let file_path = existing_file_mountpoint();
        let ops: Box<dyn FsOps> = Box::new(StubFs);
        let err = mount_background(ops, &file_path, &MountOptions::default()).unwrap_err();
        let err_text = err.to_string();
        assert!(
            err_text.contains("not a directory"),
            "expected 'not a directory' in error: {err_text}"
        );
    }

    #[test]
    fn franken_fuse_construction() {
        let _fuse = FrankenFuse::new(Box::new(StubFs));
        // Verify the Cx creation helper works.
        let _cx = FrankenFuse::cx_for_request();
    }

    #[test]
    fn encode_xattr_names_empty_is_empty_payload() {
        let encoded = FrankenFuse::encode_xattr_names(&[]);
        assert!(encoded.is_empty());
    }

    #[test]
    fn encode_xattr_names_produces_nul_separated_list() {
        let encoded = FrankenFuse::encode_xattr_names(&[
            "user.project".to_owned(),
            "security.selinux".to_owned(),
        ]);
        assert_eq!(encoded, b"user.project\0security.selinux\0");
    }

    #[test]
    fn classify_xattr_reply_size_probe_returns_size() {
        assert_eq!(
            FrankenFuse::classify_xattr_reply(0, 11),
            XattrReplyPlan::Size(11)
        );
    }

    #[test]
    fn classify_xattr_reply_data_when_buffer_fits() {
        assert_eq!(
            FrankenFuse::classify_xattr_reply(64, 32),
            XattrReplyPlan::Data
        );
    }

    #[test]
    fn classify_xattr_reply_erange_when_buffer_too_small() {
        assert_eq!(
            FrankenFuse::classify_xattr_reply(8, 32),
            XattrReplyPlan::Error(libc::ERANGE)
        );
    }

    #[test]
    fn classify_xattr_reply_eoverflow_for_oversized_payload() {
        assert_eq!(
            FrankenFuse::classify_xattr_reply(0, usize::MAX),
            XattrReplyPlan::Error(libc::EOVERFLOW)
        );
    }

    #[test]
    fn missing_xattr_errno_matches_platform() {
        #[cfg(target_os = "linux")]
        assert_eq!(FrankenFuse::missing_xattr_errno(), libc::ENODATA);

        #[cfg(not(target_os = "linux"))]
        assert_eq!(FrankenFuse::missing_xattr_errno(), libc::ENOATTR);
    }

    #[test]
    fn parse_setxattr_mode_defaults_to_set() {
        assert_eq!(
            FrankenFuse::parse_setxattr_mode(0, 0).unwrap(),
            XattrSetMode::Set
        );
    }

    #[test]
    fn parse_setxattr_mode_accepts_create_and_replace_flags() {
        assert_eq!(
            FrankenFuse::parse_setxattr_mode(XATTR_FLAG_CREATE, 0).unwrap(),
            XattrSetMode::Create
        );
        assert_eq!(
            FrankenFuse::parse_setxattr_mode(XATTR_FLAG_REPLACE, 0).unwrap(),
            XattrSetMode::Replace
        );
    }

    #[test]
    fn parse_setxattr_mode_rejects_invalid_flag_combinations() {
        assert_eq!(
            FrankenFuse::parse_setxattr_mode(XATTR_FLAG_CREATE | XATTR_FLAG_REPLACE, 0)
                .unwrap_err(),
            libc::EINVAL
        );
        assert_eq!(
            FrankenFuse::parse_setxattr_mode(0x40, 0).unwrap_err(),
            libc::EINVAL
        );
        assert_eq!(
            FrankenFuse::parse_setxattr_mode(XATTR_FLAG_CREATE, 1).unwrap_err(),
            libc::EINVAL
        );
    }

    #[test]
    fn parse_fiemap_request_reads_linux_header_layout() {
        let mut request = vec![0_u8; FIEMAP_HEADER_SIZE];
        let start = 4096_u64;
        let length = 16384_u64;
        let flags = FIEMAP_FLAG_SYNC;
        let mapped_extents = 7_u32;
        let extent_count = 3_u32;

        request[FIEMAP_START_OFFSET..FIEMAP_START_OFFSET + 8].copy_from_slice(&start.to_ne_bytes());
        request[FIEMAP_LENGTH_OFFSET..FIEMAP_LENGTH_OFFSET + 8]
            .copy_from_slice(&length.to_ne_bytes());
        request[FIEMAP_FLAGS_OFFSET..FIEMAP_FLAGS_OFFSET + 4].copy_from_slice(&flags.to_ne_bytes());
        request[FIEMAP_MAPPED_EXTENTS_OFFSET..FIEMAP_MAPPED_EXTENTS_OFFSET + 4]
            .copy_from_slice(&mapped_extents.to_ne_bytes());
        request[FIEMAP_EXTENT_COUNT_OFFSET..FIEMAP_EXTENT_COUNT_OFFSET + 4]
            .copy_from_slice(&extent_count.to_ne_bytes());

        let parsed = FrankenFuse::parse_fiemap_request(&request).expect("parse fiemap request");
        assert_eq!(parsed, (start, length, flags, extent_count));
    }

    #[test]
    fn encode_fiemap_response_writes_linux_header_offsets() {
        let extents = vec![
            FiemapExtent {
                logical: 0,
                physical: 8192,
                length: 4096,
                flags: 0,
            },
            FiemapExtent {
                logical: 4096,
                physical: 12288,
                length: 4096,
                flags: FIEMAP_EXTENT_LAST | FIEMAP_EXTENT_UNWRITTEN,
            },
        ];

        let response = FrankenFuse::encode_fiemap_response(0, u64::MAX, 8, &extents, 4096);
        assert_eq!(
            u32::from_ne_bytes(
                response[FIEMAP_MAPPED_EXTENTS_OFFSET..FIEMAP_MAPPED_EXTENTS_OFFSET + 4]
                    .try_into()
                    .expect("mapped count bytes")
            ),
            2
        );
        assert_eq!(
            u32::from_ne_bytes(
                response[FIEMAP_EXTENT_COUNT_OFFSET..FIEMAP_EXTENT_COUNT_OFFSET + 4]
                    .try_into()
                    .expect("extent count bytes")
            ),
            8
        );
        let second_extent_offset = FIEMAP_HEADER_SIZE + FIEMAP_EXTENT_SIZE;
        assert_eq!(
            u32::from_ne_bytes(
                response[second_extent_offset + 40..second_extent_offset + 44]
                    .try_into()
                    .expect("extent flags")
            ),
            FIEMAP_EXTENT_LAST | FIEMAP_EXTENT_UNWRITTEN
        );
    }

    #[test]
    fn encode_fiemap_response_limits_extents_to_output_buffer_capacity() {
        let extents = vec![
            FiemapExtent {
                logical: 0,
                physical: 4096,
                length: 4096,
                flags: 0,
            },
            FiemapExtent {
                logical: 4096,
                physical: 8192,
                length: 4096,
                flags: 0,
            },
        ];

        let response = FrankenFuse::encode_fiemap_response(
            0,
            8192,
            2,
            &extents,
            u32::try_from(FIEMAP_HEADER_SIZE + FIEMAP_EXTENT_SIZE).expect("out_size"),
        );
        assert_eq!(response.len(), FIEMAP_HEADER_SIZE + FIEMAP_EXTENT_SIZE);
        assert_eq!(
            u32::from_ne_bytes(
                response[FIEMAP_MAPPED_EXTENTS_OFFSET..FIEMAP_MAPPED_EXTENTS_OFFSET + 4]
                    .try_into()
                    .expect("mapped count bytes")
            ),
            1
        );
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum IoctlCall {
        Begin(RequestOp),
        Fiemap(InodeNumber, u64, u64),
        Fsync(InodeNumber, u64, bool),
        GetFlags(InodeNumber),
        Getattr(InodeNumber),
        GetVersion(InodeNumber),
        MoveExt(InodeNumber, u32, u64, u64, u64),
        SetFlags(InodeNumber, u32),
        Commit,
        End(RequestOp),
    }

    struct IoctlRecordingFs {
        flags: u32,
        generation: u32,
        blksize: u32,
        move_ext_result: Option<u64>,
        calls: Arc<Mutex<Vec<IoctlCall>>>,
    }

    impl IoctlRecordingFs {
        fn new(flags: u32, calls: Arc<Mutex<Vec<IoctlCall>>>) -> Self {
            Self {
                flags,
                generation: 0,
                blksize: 4096,
                move_ext_result: None,
                calls,
            }
        }

        fn with_generation(flags: u32, generation: u32, calls: Arc<Mutex<Vec<IoctlCall>>>) -> Self {
            Self {
                flags,
                generation,
                blksize: 4096,
                move_ext_result: None,
                calls,
            }
        }

        fn with_move_ext_result(moved_len: u64, calls: Arc<Mutex<Vec<IoctlCall>>>) -> Self {
            Self {
                flags: 0,
                generation: 0,
                blksize: 4096,
                move_ext_result: Some(moved_len),
                calls,
            }
        }

        fn with_move_ext_blksize(blksize: u32, calls: Arc<Mutex<Vec<IoctlCall>>>) -> Self {
            Self {
                flags: 0,
                generation: 0,
                blksize,
                move_ext_result: Some(1),
                calls,
            }
        }
    }

    fn flush_ioctl_trace_for_testing(fuse: &FrankenFuse) {
        fuse.inner
            .ioctl_trace
            .as_ref()
            .expect("ioctl trace configured")
            .flush_sync()
            .expect("ioctl trace flush_sync");
    }

    impl FsOps for IoctlRecordingFs {
        fn getattr(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
        ) -> ffs_error::Result<InodeAttr> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::Getattr(ino));
            Ok(InodeAttr {
                ino,
                size: 64 * 1024,
                blocks: 0,
                atime: SystemTime::UNIX_EPOCH,
                mtime: SystemTime::UNIX_EPOCH,
                ctime: SystemTime::UNIX_EPOCH,
                crtime: SystemTime::UNIX_EPOCH,
                kind: FfsFileType::RegularFile,
                perm: 0o644,
                nlink: 1,
                uid: 0,
                gid: 0,
                rdev: 0,
                blksize: self.blksize,
                generation: 0,
            })
        }

        fn lookup(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _parent: InodeNumber,
            _name: &OsStr,
        ) -> ffs_error::Result<InodeAttr> {
            Err(FfsError::NotFound("stub".into()))
        }

        fn readdir(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
            _offset: u64,
        ) -> ffs_error::Result<Vec<FfsDirEntry>> {
            Ok(vec![])
        }

        fn read(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
            _offset: u64,
            _size: u32,
        ) -> ffs_error::Result<Vec<u8>> {
            Ok(vec![])
        }

        fn readlink(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
        ) -> ffs_error::Result<Vec<u8>> {
            Ok(vec![])
        }

        fn get_inode_flags(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
        ) -> ffs_error::Result<u32> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::GetFlags(ino));
            Ok(self.flags)
        }

        fn get_inode_generation(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
        ) -> ffs_error::Result<u32> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::GetVersion(ino));
            Ok(self.generation)
        }

        fn fiemap(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
            start: u64,
            length: u64,
        ) -> ffs_error::Result<Vec<FiemapExtent>> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::Fiemap(ino, start, length));
            Ok(vec![])
        }

        fn fsync(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
            fh: u64,
            datasync: bool,
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::Fsync(ino, fh, datasync));
            Ok(())
        }

        fn set_inode_flags(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
            flags: u32,
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::SetFlags(ino, flags));
            Ok(())
        }

        fn move_ext(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
            donor_fd: u32,
            orig_start: u64,
            donor_start: u64,
            len: u64,
        ) -> ffs_error::Result<u64> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::MoveExt(
                    ino,
                    donor_fd,
                    orig_start,
                    donor_start,
                    len,
                ));
            Ok(self.move_ext_result.unwrap_or(len))
        }

        fn begin_request_scope(&self, _cx: &Cx, op: RequestOp) -> ffs_error::Result<RequestScope> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::Begin(op));
            Ok(RequestScope::empty())
        }

        fn end_request_scope(
            &self,
            _cx: &Cx,
            op: RequestOp,
            _scope: RequestScope,
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::End(op));
            Ok(())
        }

        fn commit_request_scope(&self, _scope: &mut RequestScope) -> ffs_error::Result<CommitSeq> {
            self.calls
                .lock()
                .expect("lock ioctl calls")
                .push(IoctlCall::Commit);
            Ok(CommitSeq(1))
        }
    }

    #[test]
    fn dispatch_ioctl_getflags_encodes_u32_response_for_fileattr_path() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(
            0x1234_5678,
            Arc::clone(&calls),
        )));

        let response = fuse.dispatch_ioctl(11, 0, EXT4_IOC_GETFLAGS, &[], 4);
        assert!(
            matches!(response, IoctlResult::Data(_)),
            "expected ioctl data response"
        );
        let IoctlResult::Data(bytes) = response else {
            unreachable!("asserted IoctlResult::Data above");
        };
        assert_eq!(bytes.len(), 4);
        assert_eq!(
            u32::from_ne_bytes(bytes.try_into().expect("4-byte ioctl payload")),
            0x1234_5678_u32
        );
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::GetFlags(InodeNumber(11)),
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_getflags_rejects_too_small_output_buffer() {
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(
            0x1234_5678,
            Arc::new(Mutex::new(Vec::new())),
        )));

        let response = fuse.dispatch_ioctl(11, 0, EXT4_IOC_GETFLAGS, &[], 3);
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
    }

    #[test]
    fn dispatch_ioctl_getversion_encodes_u32_response_for_inode_generation() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::with_generation(
            0,
            0xDEAD_BEEF,
            Arc::clone(&calls),
        )));

        let response = fuse.dispatch_ioctl(11, 0, EXT4_IOC_GETVERSION, &[], 4);
        assert!(
            matches!(response, IoctlResult::Data(_)),
            "expected ioctl data response"
        );
        let IoctlResult::Data(bytes) = response else {
            unreachable!("asserted IoctlResult::Data above");
        };
        assert_eq!(bytes.len(), 4);
        assert_eq!(
            u32::from_ne_bytes(bytes.try_into().expect("4-byte ioctl payload")),
            0xDEAD_BEEF_u32
        );
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::GetVersion(InodeNumber(11)),
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_getversion_rejects_too_small_output_buffer() {
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::with_generation(
            0,
            7,
            Arc::new(Mutex::new(Vec::new())),
        )));

        let response = fuse.dispatch_ioctl(11, 0, EXT4_IOC_GETVERSION, &[], 3);
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
    }

    #[test]
    fn dispatch_ioctl_setflags_rejects_read_only_mount() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));

        let response = fuse.dispatch_ioctl(7, 0, EXT4_IOC_SETFLAGS, &1_u32.to_ne_bytes(), 0);
        assert_eq!(response, IoctlResult::Error(libc::EROFS));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_setflags_routes_to_fsops_and_commits() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &options,
        );

        let response = fuse.dispatch_ioctl(9, 0, EXT4_IOC_SETFLAGS, &0x42_u32.to_ne_bytes(), 0);
        assert_eq!(response, IoctlResult::Data(Vec::new()));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlWrite),
                IoctlCall::SetFlags(InodeNumber(9), 0x42),
                IoctlCall::Commit,
                IoctlCall::End(RequestOp::IoctlWrite),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_setflags_accepts_8_byte_long_payload_by_using_low_u32() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &options,
        );

        let response = fuse.dispatch_ioctl(
            9,
            0,
            EXT4_IOC_SETFLAGS,
            &0x0000_0001_0000_0042_u64.to_ne_bytes(),
            0,
        );
        assert_eq!(response, IoctlResult::Data(Vec::new()));
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlWrite),
                IoctlCall::SetFlags(InodeNumber(9), 0x42),
                IoctlCall::Commit,
                IoctlCall::End(RequestOp::IoctlWrite),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_move_ext_rejects_read_only_mount() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));
        let request = FrankenFuse::encode_move_ext_response(7, 11, 22, 33, 0);

        let response = fuse.dispatch_ioctl(
            9,
            0,
            EXT4_IOC_MOVE_EXT,
            &request,
            u32::try_from(MOVE_EXT_SIZE).expect("move_ext size fits"),
        );
        assert_eq!(response, IoctlResult::Error(libc::EROFS));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_move_ext_rejects_too_short_payload() {
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::new(Mutex::new(Vec::new())))),
            &options,
        );

        let response = fuse.dispatch_ioctl(5, 0, EXT4_IOC_MOVE_EXT, &[0_u8; 16], 40);
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
    }

    #[test]
    fn dispatch_ioctl_move_ext_rejects_nonzero_reserved_field() {
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::new(Mutex::new(Vec::new())))),
            &options,
        );
        let mut request = FrankenFuse::encode_move_ext_response(7, 11, 22, 33, 0);
        request[MOVE_EXT_RESERVED_OFFSET..MOVE_EXT_RESERVED_OFFSET + 4]
            .copy_from_slice(&1_u32.to_ne_bytes());

        let response = fuse.dispatch_ioctl(
            5,
            0,
            EXT4_IOC_MOVE_EXT,
            &request,
            u32::try_from(MOVE_EXT_SIZE).expect("move_ext size fits"),
        );
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
    }

    #[test]
    fn dispatch_ioctl_move_ext_rejects_overflowing_ranges() {
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::new(Mutex::new(Vec::new())))),
            &options,
        );

        let request = FrankenFuse::encode_move_ext_response(7, u64::MAX, 22, 1, 0);
        let response = fuse.dispatch_ioctl(
            5,
            0,
            EXT4_IOC_MOVE_EXT,
            &request,
            u32::try_from(MOVE_EXT_SIZE).expect("move_ext size fits"),
        );
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));

        let request = FrankenFuse::encode_move_ext_response(7, 11, u64::MAX, 1, 0);
        let response = fuse.dispatch_ioctl(
            5,
            0,
            EXT4_IOC_MOVE_EXT,
            &request,
            u32::try_from(MOVE_EXT_SIZE).expect("move_ext size fits"),
        );
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
    }

    #[test]
    fn dispatch_ioctl_move_ext_rejects_misaligned_page_offsets() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::with_move_ext_blksize(
                1024,
                Arc::clone(&calls),
            )),
            &options,
        );
        let request = FrankenFuse::encode_move_ext_response(7, 1, 2, 1, 0);

        let response = fuse.dispatch_ioctl(
            5,
            0,
            EXT4_IOC_MOVE_EXT,
            &request,
            u32::try_from(MOVE_EXT_SIZE).expect("move_ext size fits"),
        );
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
    }

    #[test]
    fn dispatch_ioctl_move_ext_rejects_ext_max_blocks_boundaries() {
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::new(Mutex::new(Vec::new())))),
            &options,
        );

        let request = FrankenFuse::encode_move_ext_response(7, EXT4_MOVE_EXT_MAX_BLOCKS, 0, 1, 0);
        let response = fuse.dispatch_ioctl(
            5,
            0,
            EXT4_IOC_MOVE_EXT,
            &request,
            u32::try_from(MOVE_EXT_SIZE).expect("move_ext size fits"),
        );
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));

        let request =
            FrankenFuse::encode_move_ext_response(7, EXT4_MOVE_EXT_MAX_BLOCKS - 1, 0, 1, 0);
        let response = fuse.dispatch_ioctl(
            5,
            0,
            EXT4_IOC_MOVE_EXT,
            &request,
            u32::try_from(MOVE_EXT_SIZE).expect("move_ext size fits"),
        );
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
    }

    #[test]
    fn dispatch_ioctl_move_ext_rejects_too_small_output_buffer() {
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::new(Mutex::new(Vec::new())))),
            &options,
        );
        let request = FrankenFuse::encode_move_ext_response(7, 11, 22, 33, 0);

        let response = fuse.dispatch_ioctl(
            5,
            0,
            EXT4_IOC_MOVE_EXT,
            &request,
            u32::try_from(MOVE_EXT_SIZE - 1).expect("move_ext size fits"),
        );
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
    }

    #[test]
    fn dispatch_ioctl_move_ext_routes_to_fsops_and_commits() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::with_move_ext_result(
                21,
                Arc::clone(&calls),
            )),
            &options,
        );
        let request = FrankenFuse::encode_move_ext_response(7, 11, 22, 33, 0);

        let response = fuse.dispatch_ioctl(
            9,
            0,
            EXT4_IOC_MOVE_EXT,
            &request,
            u32::try_from(MOVE_EXT_SIZE).expect("move_ext size fits"),
        );
        assert_eq!(
            response,
            IoctlResult::Data(FrankenFuse::encode_move_ext_response(7, 11, 22, 33, 21))
        );
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::IoctlWrite),
                IoctlCall::Getattr(InodeNumber(9)),
                IoctlCall::MoveExt(InodeNumber(9), 7, 11, 22, 33),
                IoctlCall::Commit,
                IoctlCall::End(RequestOp::IoctlWrite),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_fiemap_rejects_unsupported_request_flags() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))));
        let mut request = vec![0_u8; FIEMAP_HEADER_SIZE];
        request[FIEMAP_LENGTH_OFFSET..FIEMAP_LENGTH_OFFSET + 8]
            .copy_from_slice(&4096_u64.to_ne_bytes());
        request[FIEMAP_FLAGS_OFFSET..FIEMAP_FLAGS_OFFSET + 4]
            .copy_from_slice(&FIEMAP_FLAG_XATTR.to_ne_bytes());

        let response = fuse.dispatch_ioctl(
            5,
            0,
            FS_IOC_FIEMAP,
            &request,
            u32::try_from(FIEMAP_HEADER_SIZE).expect("header size fits"),
        );
        assert_eq!(response, IoctlResult::Error(libc::EBADR));
        assert!(calls.lock().expect("lock ioctl calls").is_empty());
    }

    #[test]
    fn dispatch_ioctl_fiemap_sync_fsyncs_before_extent_lookup() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::clone(&calls))),
            &options,
        );
        let mut request = vec![0_u8; FIEMAP_HEADER_SIZE];
        request[FIEMAP_START_OFFSET..FIEMAP_START_OFFSET + 8]
            .copy_from_slice(&8192_u64.to_ne_bytes());
        request[FIEMAP_LENGTH_OFFSET..FIEMAP_LENGTH_OFFSET + 8]
            .copy_from_slice(&4096_u64.to_ne_bytes());
        request[FIEMAP_FLAGS_OFFSET..FIEMAP_FLAGS_OFFSET + 4]
            .copy_from_slice(&FIEMAP_FLAG_SYNC.to_ne_bytes());

        let response = fuse.dispatch_ioctl(
            13,
            91,
            FS_IOC_FIEMAP,
            &request,
            u32::try_from(FIEMAP_HEADER_SIZE).expect("header size fits"),
        );
        assert_eq!(
            response,
            IoctlResult::Data(FrankenFuse::encode_fiemap_response(8192, 4096, 0, &[], 32))
        );
        assert_eq!(
            calls.lock().expect("lock ioctl calls").as_slice(),
            &[
                IoctlCall::Begin(RequestOp::Fsync),
                IoctlCall::Fsync(InodeNumber(13), 91, false),
                IoctlCall::Commit,
                IoctlCall::End(RequestOp::Fsync),
                IoctlCall::Begin(RequestOp::IoctlRead),
                IoctlCall::Fiemap(InodeNumber(13), 8192, 4096),
                IoctlCall::End(RequestOp::IoctlRead),
            ]
        );
    }

    #[test]
    fn dispatch_ioctl_unknown_command_returns_enotty() {
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(
            0,
            Arc::new(Mutex::new(Vec::new())),
        )));

        let response = fuse.dispatch_ioctl(1, 0, 0xDEAD_BEEF, &[], 0);
        assert_eq!(response, IoctlResult::Error(libc::ENOTTY));
    }

    #[test]
    fn record_ioctl_probe_appends_lines_via_buffered_sink() {
        let unique = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_nanos();
        let trace_path = std::env::temp_dir().join(format!(
            "ffs_fuse_ioctl_trace_{}_{}.log",
            std::process::id(),
            unique
        ));
        std::fs::write(&trace_path, "seed\n").expect("seed ioctl trace");
        let options = MountOptions {
            ioctl_trace_path: Some(trace_path.clone()),
            ..MountOptions::default()
        };

        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(
                0x1234_5678,
                Arc::new(Mutex::new(Vec::new())),
            )),
            &options,
        );

        fuse.record_ioctl_probe(11, EXT4_IOC_GETFLAGS, 0, 4);
        fuse.record_ioctl_probe(12, 0xDEAD_BEEF, 0, 0);
        flush_ioctl_trace_for_testing(&fuse);

        let trace = std::fs::read_to_string(&trace_path).expect("read ioctl trace");
        let lines = trace.lines().collect::<Vec<_>>();
        assert_eq!(
            lines,
            vec![
                "seed",
                "ino=11 cmd=0x80086601 in_len=0 out_size=4",
                "ino=12 cmd=0xdeadbeef in_len=0 out_size=0",
            ]
        );
    }

    #[test]
    fn ioctl_trace_flush_sync_is_happens_before_barrier_for_concurrent_recorders() {
        // Spawning many threads that all enqueue records concurrently, then
        // a single `flush_sync` from the main thread, must guarantee that
        // every previously enqueued record is visible in the on-disk file by
        // the time `flush_sync` returns.  This is the core contract of the
        // off-thread writer: the dispatcher never blocks on file I/O, but
        // tests get a deterministic synchronisation point.
        const RECORDER_THREADS: usize = 8;
        const RECORDS_PER_THREAD: usize = 32;

        let unique = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("system time after unix epoch")
            .as_nanos();
        let trace_path = std::env::temp_dir().join(format!(
            "ffs_fuse_ioctl_trace_concurrent_{}_{}.log",
            std::process::id(),
            unique
        ));
        let options = MountOptions {
            ioctl_trace_path: Some(trace_path.clone()),
            ..MountOptions::default()
        };
        let fuse = Arc::new(FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::new(Mutex::new(Vec::new())))),
            &options,
        ));

        let barrier = Arc::new(std::sync::Barrier::new(RECORDER_THREADS));
        let mut handles = Vec::with_capacity(RECORDER_THREADS);
        for thread_idx in 0..RECORDER_THREADS {
            let fuse = Arc::clone(&fuse);
            let barrier = Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                for record_idx in 0..RECORDS_PER_THREAD {
                    fuse.record_ioctl_probe(
                        (thread_idx * RECORDS_PER_THREAD + record_idx) as u64,
                        EXT4_IOC_GETFLAGS,
                        0,
                        4,
                    );
                }
            }));
        }
        for h in handles {
            h.join().expect("recorder thread");
        }
        flush_ioctl_trace_for_testing(&fuse);

        let trace = std::fs::read_to_string(&trace_path).expect("read ioctl trace");
        let line_count = trace.lines().count();
        assert_eq!(
            line_count,
            RECORDER_THREADS * RECORDS_PER_THREAD,
            "every recorded ioctl event must be visible after flush_sync; \
             channel capacity ({IOCTL_TRACE_CHANNEL_CAPACITY}) is far above this test's load"
        );
    }

    #[test]
    fn dispatch_ioctl_setflags_rejects_too_short_payload() {
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(IoctlRecordingFs::new(0, Arc::new(Mutex::new(Vec::new())))),
            &options,
        );

        // 3 bytes is too short for a u32 flags value.
        let response = fuse.dispatch_ioctl(5, 0, EXT4_IOC_SETFLAGS, &[0x01, 0x02, 0x03], 0);
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));

        // Empty payload is also rejected.
        let response = fuse.dispatch_ioctl(5, 0, EXT4_IOC_SETFLAGS, &[], 0);
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
    }

    #[test]
    fn dispatch_ioctl_fiemap_rejects_truncated_header() {
        let fuse = FrankenFuse::new(Box::new(IoctlRecordingFs::new(
            0,
            Arc::new(Mutex::new(Vec::new())),
        )));

        // Header shorter than FIEMAP_HEADER_SIZE (32 bytes).
        let short_header = vec![0_u8; 16];
        let response = fuse.dispatch_ioctl(
            3,
            0,
            FS_IOC_FIEMAP,
            &short_header,
            u32::try_from(FIEMAP_HEADER_SIZE).expect("header size fits"),
        );
        assert_eq!(response, IoctlResult::Error(libc::EINVAL));
    }

    #[test]
    fn access_predictor_doubles_fetch_size_for_forward_sequence() {
        let predictor = AccessPredictor::default();
        let ino = InodeNumber(11);
        let size = 4096_u32;

        assert_eq!(predictor.fetch_size(ino, 0, size), size);
        predictor.record_read(ino, 0, size);
        assert_eq!(predictor.fetch_size(ino, u64::from(size), size), size);

        predictor.record_read(ino, u64::from(size), size);
        assert_eq!(
            predictor.fetch_size(ino, u64::from(size) * 2, size),
            size.saturating_mul(COALESCED_FETCH_MULTIPLIER)
                .min(MAX_COALESCED_READ_SIZE)
        );
    }

    #[test]
    fn readahead_manager_partial_take_requeues_tail() {
        let manager = ReadaheadManager::new(8);
        let ino = InodeNumber(5);

        manager.insert(ino, 100, vec![1, 2, 3, 4, 5, 6]);
        assert_eq!(manager.take(ino, 100, 4), Some(vec![1, 2, 3, 4]));
        assert_eq!(manager.take(ino, 104, 8), Some(vec![5, 6]));
    }

    #[test]
    fn readahead_manager_tail_requeue_refreshes_fifo_order() {
        let manager = ReadaheadManager::new(3);
        let ino = InodeNumber(6);

        manager.insert(ino, 0, vec![1, 2, 3, 4, 5, 6]);
        manager.insert(ino, 4, vec![9, 9]);
        manager.insert(ino, 8, vec![7, 7]);

        assert_eq!(manager.take(ino, 0, 4), Some(vec![1, 2, 3, 4]));

        manager.insert(ino, 12, vec![8, 8]);
        manager.insert(ino, 16, vec![9, 9]);

        assert_eq!(manager.take(ino, 8, 2), None);
        assert_eq!(manager.take(ino, 4, 2), Some(vec![5, 6]));
    }

    #[test]
    fn readahead_manager_zero_len_take_preserves_entry() {
        let manager = ReadaheadManager::new(8);
        let ino = InodeNumber(7);

        manager.insert(ino, 0, vec![1, 2, 3]);
        assert_eq!(manager.take(ino, 0, 0), None);
        assert_eq!(manager.take(ino, 0, 3), Some(vec![1, 2, 3]));
    }

    #[test]
    fn readahead_manager_caps_pending_entries() {
        let manager = ReadaheadManager::new(2);
        let ino = InodeNumber(9);

        manager.insert(ino, 0, vec![0]);
        manager.insert(ino, 8, vec![1]);
        manager.insert(ino, 16, vec![2]);

        assert_eq!(manager.take(ino, 0, 1), None);
        assert_eq!(manager.take(ino, 8, 1), Some(vec![1]));
        assert_eq!(manager.take(ino, 16, 1), Some(vec![2]));
    }

    #[test]
    fn readahead_manager_reinsert_refreshes_fifo_order() {
        let manager = ReadaheadManager::new(2);
        let ino = InodeNumber(11);

        manager.insert(ino, 0, vec![1]);
        manager.insert(ino, 8, vec![2]);
        // Reinsert offset 0 to refresh its FIFO position.
        manager.insert(ino, 0, vec![3]);
        manager.insert(ino, 16, vec![4]); // Evicts the oldest remaining entry.

        assert_eq!(manager.take(ino, 8, 1), None);
        assert_eq!(manager.take(ino, 0, 1), Some(vec![3]));
        assert_eq!(manager.take(ino, 16, 1), Some(vec![4]));
    }

    #[test]
    fn readahead_manager_invalidate_inode_removes_only_matching_entries() {
        let manager = ReadaheadManager::new(8);
        let ino = InodeNumber(9);
        let other = InodeNumber(10);

        manager.insert(ino, 0, vec![1, 2, 3]);
        manager.insert(ino, 16, vec![4, 5, 6]);
        manager.insert(other, 0, vec![7, 8, 9]);

        manager.invalidate_inode(ino);

        assert_eq!(manager.take(ino, 0, 3), None);
        assert_eq!(manager.take(ino, 16, 3), None);
        assert_eq!(manager.take(other, 0, 3), Some(vec![7, 8, 9]));
    }

    struct CountingReadFs {
        data: Vec<u8>,
        read_calls: Arc<AtomicU64>,
    }

    impl CountingReadFs {
        fn new(data: Vec<u8>, read_calls: Arc<AtomicU64>) -> Self {
            Self { data, read_calls }
        }
    }

    impl FsOps for CountingReadFs {
        fn getattr(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
        ) -> ffs_error::Result<InodeAttr> {
            Err(FfsError::NotFound("stub".into()))
        }

        fn lookup(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _parent: InodeNumber,
            _name: &OsStr,
        ) -> ffs_error::Result<InodeAttr> {
            Err(FfsError::NotFound("stub".into()))
        }

        fn readdir(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
            _offset: u64,
        ) -> ffs_error::Result<Vec<FfsDirEntry>> {
            Ok(vec![])
        }

        fn read(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
            offset: u64,
            size: u32,
        ) -> ffs_error::Result<Vec<u8>> {
            self.read_calls.fetch_add(1, Ordering::Relaxed);
            let start = usize::try_from(offset).unwrap_or(usize::MAX);
            if start >= self.data.len() {
                return Ok(vec![]);
            }
            let requested = usize::try_from(size).unwrap_or(usize::MAX);
            let end = start.saturating_add(requested).min(self.data.len());
            Ok(self.data[start..end].to_vec())
        }

        fn readlink(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
        ) -> ffs_error::Result<Vec<u8>> {
            Ok(vec![])
        }
    }

    #[test]
    fn sequential_reads_use_prefetched_tail_without_extra_backend_call() {
        let read_calls = Arc::new(AtomicU64::new(0));
        let data: Vec<u8> = (0_u8..64).collect();
        let fuse = FrankenFuse::new(Box::new(CountingReadFs::new(data, Arc::clone(&read_calls))));
        let cx = Cx::for_testing();
        let ino = InodeNumber(1);

        assert_eq!(
            fuse.read_with_readahead(&cx, ino, 0, 4).unwrap(),
            vec![0, 1, 2, 3]
        );
        assert_eq!(
            fuse.read_with_readahead(&cx, ino, 4, 4).unwrap(),
            vec![4, 5, 6, 7]
        );
        assert_eq!(
            fuse.read_with_readahead(&cx, ino, 8, 4).unwrap(),
            vec![8, 9, 10, 11]
        );
        assert_eq!(
            fuse.read_with_readahead(&cx, ino, 12, 4).unwrap(),
            vec![12, 13, 14, 15]
        );

        // The third read uses a doubled fetch and queues the tail for the
        // fourth read, so only three backend reads are needed.
        assert_eq!(read_calls.load(Ordering::Relaxed), 3);
    }

    #[test]
    fn long_sequential_reads_exceed_two_x_call_reduction() {
        let read_calls = Arc::new(AtomicU64::new(0));
        let data: Vec<u8> = (0_u8..128).collect();
        let fuse = FrankenFuse::new(Box::new(CountingReadFs::new(data, Arc::clone(&read_calls))));
        let cx = Cx::for_testing();
        let ino = InodeNumber(2);

        for index in 0_u64..12 {
            let offset = index * 4;
            let expected_start = u8::try_from(offset).unwrap_or(u8::MAX);
            let expected = vec![
                expected_start,
                expected_start.saturating_add(1),
                expected_start.saturating_add(2),
                expected_start.saturating_add(3),
            ];
            assert_eq!(
                fuse.read_with_readahead(&cx, ino, offset, 4).unwrap(),
                expected
            );
        }

        // 12 logical reads complete with at most 5 backend reads, which is
        // >2x reduction versus the unbatched baseline of 12 calls.
        assert!(read_calls.load(Ordering::Relaxed) <= 5);
    }

    #[test]
    fn non_sequential_reads_do_not_trigger_coalescing() {
        let read_calls = Arc::new(AtomicU64::new(0));
        let data: Vec<u8> = (0_u8..128).collect();
        let fuse = FrankenFuse::new(Box::new(CountingReadFs::new(data, Arc::clone(&read_calls))));
        let cx = Cx::for_testing();
        let ino = InodeNumber(3);
        let offsets = [0_u64, 32, 4, 48, 8, 64];

        for offset in offsets {
            let _ = fuse.read_with_readahead(&cx, ino, offset, 4).unwrap();
        }

        assert_eq!(
            read_calls.load(Ordering::Relaxed),
            u64::try_from(offsets.len()).unwrap_or(u64::MAX)
        );
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum HookEvent {
        Begin(RequestOp),
        Body(RequestOp),
        End(RequestOp),
    }

    struct HookFs {
        events: Arc<Mutex<Vec<HookEvent>>>,
        fail_begin: bool,
        fail_end: bool,
    }

    impl HookFs {
        fn new(events: Arc<Mutex<Vec<HookEvent>>>, fail_begin: bool, fail_end: bool) -> Self {
            Self {
                events,
                fail_begin,
                fail_end,
            }
        }
    }

    impl FsOps for HookFs {
        fn getattr(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
        ) -> ffs_error::Result<InodeAttr> {
            Err(FfsError::NotFound("stub".into()))
        }

        fn lookup(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _parent: InodeNumber,
            _name: &OsStr,
        ) -> ffs_error::Result<InodeAttr> {
            Err(FfsError::NotFound("stub".into()))
        }

        fn readdir(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
            _offset: u64,
        ) -> ffs_error::Result<Vec<FfsDirEntry>> {
            Ok(vec![])
        }

        fn read(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
            _offset: u64,
            _size: u32,
        ) -> ffs_error::Result<Vec<u8>> {
            Ok(vec![])
        }

        fn readlink(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
        ) -> ffs_error::Result<Vec<u8>> {
            Ok(vec![])
        }

        fn begin_request_scope(&self, _cx: &Cx, op: RequestOp) -> ffs_error::Result<RequestScope> {
            self.events.lock().unwrap().push(HookEvent::Begin(op));
            if self.fail_begin {
                return Err(FfsError::Io(std::io::Error::other("begin failed")));
            }
            Ok(RequestScope::empty())
        }

        fn end_request_scope(
            &self,
            _cx: &Cx,
            op: RequestOp,
            _scope: RequestScope,
        ) -> ffs_error::Result<()> {
            self.events.lock().unwrap().push(HookEvent::End(op));
            if self.fail_end {
                return Err(FfsError::Io(std::io::Error::other("end failed")));
            }
            Ok(())
        }
    }

    #[test]
    fn request_scope_calls_begin_and_end_for_successful_operation() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let fs = HookFs::new(Arc::clone(&events), false, false);
        let fuse = FrankenFuse::new(Box::new(fs));
        let cx = Cx::for_testing();
        let body_events = Arc::clone(&events);

        let out = fuse
            .with_request_scope(&cx, RequestOp::Read, |_cx, _scope| {
                body_events
                    .lock()
                    .unwrap()
                    .push(HookEvent::Body(RequestOp::Read));
                Ok::<u32, FfsError>(7)
            })
            .unwrap();
        assert_eq!(out, 7);
        assert_eq!(
            events.lock().unwrap().as_slice(),
            &[
                HookEvent::Begin(RequestOp::Read),
                HookEvent::Body(RequestOp::Read),
                HookEvent::End(RequestOp::Read)
            ]
        );
    }

    #[test]
    fn request_scope_short_circuits_body_when_begin_fails() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let fs = HookFs::new(Arc::clone(&events), true, false);
        let fuse = FrankenFuse::new(Box::new(fs));
        let cx = Cx::for_testing();
        let body_called = Arc::new(AtomicBool::new(false));
        let body_called_ref = Arc::clone(&body_called);

        let err = fuse
            .with_request_scope(&cx, RequestOp::Lookup, |_cx, _scope| {
                body_called_ref.store(true, Ordering::Relaxed);
                Ok::<(), FfsError>(())
            })
            .unwrap_err();
        assert_eq!(err.to_errno(), libc::EIO);
        assert!(!body_called.load(Ordering::Relaxed));
        assert_eq!(
            events.lock().unwrap().as_slice(),
            &[HookEvent::Begin(RequestOp::Lookup)]
        );
        let metrics = fuse.metrics().snapshot();
        assert_eq!(metrics.requests_total, 1);
        assert_eq!(metrics.requests_ok, 0);
        assert_eq!(metrics.requests_err, 1);
    }

    #[test]
    fn request_scope_prefers_operation_error_when_body_and_end_fail() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let fs = HookFs::new(Arc::clone(&events), false, true);
        let fuse = FrankenFuse::new(Box::new(fs));
        let cx = Cx::for_testing();
        let body_events = Arc::clone(&events);

        let err = fuse
            .with_request_scope(&cx, RequestOp::Readlink, |_cx, _scope| {
                body_events
                    .lock()
                    .unwrap()
                    .push(HookEvent::Body(RequestOp::Readlink));
                Err::<(), FfsError>(FfsError::NotFound("missing".into()))
            })
            .unwrap_err();
        assert_eq!(err.to_errno(), libc::ENOENT);
        assert_eq!(
            events.lock().unwrap().as_slice(),
            &[
                HookEvent::Begin(RequestOp::Readlink),
                HookEvent::Body(RequestOp::Readlink),
                HookEvent::End(RequestOp::Readlink)
            ]
        );
    }

    #[test]
    fn request_scope_returns_cleanup_error_when_operation_succeeds() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let fs = HookFs::new(Arc::clone(&events), false, true);
        let fuse = FrankenFuse::new(Box::new(fs));
        let cx = Cx::for_testing();
        let body_events = Arc::clone(&events);

        let err = fuse
            .with_request_scope(&cx, RequestOp::Getattr, |_cx, _scope| {
                body_events
                    .lock()
                    .unwrap()
                    .push(HookEvent::Body(RequestOp::Getattr));
                Ok::<(), FfsError>(())
            })
            .unwrap_err();
        assert_eq!(err.to_errno(), libc::EIO);
        assert_eq!(
            events.lock().unwrap().as_slice(),
            &[
                HookEvent::Begin(RequestOp::Getattr),
                HookEvent::Body(RequestOp::Getattr),
                HookEvent::End(RequestOp::Getattr)
            ]
        );
    }

    fn test_inode_attr(ino: u64, kind: FfsFileType, perm: u16) -> InodeAttr {
        InodeAttr {
            ino: InodeNumber(ino),
            size: 0,
            blocks: 0,
            atime: SystemTime::UNIX_EPOCH,
            mtime: SystemTime::UNIX_EPOCH,
            ctime: SystemTime::UNIX_EPOCH,
            crtime: SystemTime::UNIX_EPOCH,
            kind,
            perm,
            nlink: 1,
            uid: 1000,
            gid: 1000,
            rdev: 0,
            blksize: 4096,
            generation: 1,
        }
    }

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum MutationCall {
        Write {
            ino: InodeNumber,
            offset: u64,
            data: Vec<u8>,
        },
        Mkdir {
            parent: InodeNumber,
            name: String,
            mode: u16,
            uid: u32,
            gid: u32,
        },
        Rmdir {
            parent: InodeNumber,
            name: String,
        },
        Rename {
            parent: InodeNumber,
            name: String,
            new_parent: InodeNumber,
            new_name: String,
        },
    }

    struct MutationRecordingFs {
        calls: Arc<Mutex<Vec<MutationCall>>>,
    }

    impl MutationRecordingFs {
        fn new(calls: Arc<Mutex<Vec<MutationCall>>>) -> Self {
            Self { calls }
        }
    }

    impl FsOps for MutationRecordingFs {
        fn getattr(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
        ) -> ffs_error::Result<InodeAttr> {
            Err(FfsError::NotFound("stub".into()))
        }

        fn lookup(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _parent: InodeNumber,
            _name: &OsStr,
        ) -> ffs_error::Result<InodeAttr> {
            Err(FfsError::NotFound("stub".into()))
        }

        fn readdir(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
            _offset: u64,
        ) -> ffs_error::Result<Vec<FfsDirEntry>> {
            Ok(vec![])
        }

        fn read(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
            _offset: u64,
            _size: u32,
        ) -> ffs_error::Result<Vec<u8>> {
            Ok(vec![])
        }

        fn readlink(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            _ino: InodeNumber,
        ) -> ffs_error::Result<Vec<u8>> {
            Ok(vec![])
        }

        fn mkdir(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            parent: InodeNumber,
            name: &OsStr,
            mode: u16,
            uid: u32,
            gid: u32,
        ) -> ffs_error::Result<InodeAttr> {
            self.calls
                .lock()
                .expect("lock mutation calls")
                .push(MutationCall::Mkdir {
                    parent,
                    name: name.to_string_lossy().into_owned(),
                    mode,
                    uid,
                    gid,
                });
            Ok(test_inode_attr(101, FfsFileType::Directory, mode))
        }

        fn rmdir(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            parent: InodeNumber,
            name: &OsStr,
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock mutation calls")
                .push(MutationCall::Rmdir {
                    parent,
                    name: name.to_string_lossy().into_owned(),
                });
            Ok(())
        }

        fn rename(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            parent: InodeNumber,
            name: &OsStr,
            new_parent: InodeNumber,
            new_name: &OsStr,
        ) -> ffs_error::Result<()> {
            self.calls
                .lock()
                .expect("lock mutation calls")
                .push(MutationCall::Rename {
                    parent,
                    name: name.to_string_lossy().into_owned(),
                    new_parent,
                    new_name: new_name.to_string_lossy().into_owned(),
                });
            Ok(())
        }

        fn write(
            &self,
            _cx: &Cx,
            _scope: &mut RequestScope,
            ino: InodeNumber,
            offset: u64,
            data: &[u8],
        ) -> ffs_error::Result<u32> {
            self.calls
                .lock()
                .expect("lock mutation calls")
                .push(MutationCall::Write {
                    ino,
                    offset,
                    data: data.to_vec(),
                });
            Ok(u32::try_from(data.len()).unwrap_or(u32::MAX))
        }
    }

    #[test]
    fn dispatch_write_routes_to_fsops() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::new(Arc::clone(&calls))),
            &options,
        );

        let written = fuse
            .dispatch_write(42, 4096, b"abc")
            .expect("dispatch write");
        assert_eq!(written, 3);
        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[MutationCall::Write {
                ino: InodeNumber(42),
                offset: 4096,
                data: b"abc".to_vec(),
            }]
        );
    }

    #[test]
    fn dispatch_write_invalidates_readahead_for_inode() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::new(Arc::clone(&calls))),
            &options,
        );

        let cached_ino = InodeNumber(42);
        let other_ino = InodeNumber(77);
        fuse.inner.readahead.insert(cached_ino, 100, vec![1, 2, 3]);
        fuse.inner.readahead.insert(other_ino, 100, vec![9, 9, 9]);

        let written = fuse
            .dispatch_write(cached_ino.0, 0, b"abc")
            .expect("dispatch write");
        assert_eq!(written, 3);

        assert_eq!(fuse.inner.readahead.take(cached_ino, 100, 3), None);
        assert_eq!(
            fuse.inner.readahead.take(other_ino, 100, 3),
            Some(vec![9, 9, 9])
        );
    }

    #[test]
    fn dispatch_mkdir_routes_to_fsops() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::new(Arc::clone(&calls))),
            &options,
        );

        let attr = fuse
            .dispatch_mkdir(2, OsStr::new("logs"), 0o755, 123, 456)
            .expect("dispatch mkdir");
        assert_eq!(attr.ino, InodeNumber(101));
        assert_eq!(attr.kind, FfsFileType::Directory);
        assert_eq!(attr.perm, 0o755);
        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[MutationCall::Mkdir {
                parent: InodeNumber(2),
                name: "logs".to_owned(),
                mode: 0o755,
                uid: 123,
                gid: 456,
            }]
        );
    }

    #[test]
    fn dispatch_rmdir_routes_to_fsops() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::new(Arc::clone(&calls))),
            &options,
        );

        fuse.dispatch_rmdir(7, OsStr::new("tmp"))
            .expect("dispatch rmdir");
        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[MutationCall::Rmdir {
                parent: InodeNumber(7),
                name: "tmp".to_owned(),
            }]
        );
    }

    #[test]
    fn dispatch_rename_routes_to_fsops() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::new(Arc::clone(&calls))),
            &options,
        );

        fuse.dispatch_rename(8, OsStr::new("old"), 9, OsStr::new("new"))
            .expect("dispatch rename");
        assert_eq!(
            calls.lock().expect("lock calls").as_slice(),
            &[MutationCall::Rename {
                parent: InodeNumber(8),
                name: "old".to_owned(),
                new_parent: InodeNumber(9),
                new_name: "new".to_owned(),
            }]
        );
    }

    #[test]
    fn dispatch_write_rejects_negative_offset() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(
            Box::new(MutationRecordingFs::new(Arc::clone(&calls))),
            &options,
        );

        let err = fuse
            .dispatch_write(99, -1, b"z")
            .expect_err("negative offset should fail");
        assert!(matches!(err, MutationDispatchError::Errno(libc::EINVAL)));
        assert!(calls.lock().expect("lock calls").is_empty());
    }

    #[test]
    fn dispatch_mutations_return_erofs_when_read_only() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let fuse = FrankenFuse::new(Box::new(MutationRecordingFs::new(Arc::clone(&calls))));

        assert!(matches!(
            fuse.dispatch_write(1, 0, b"x"),
            Err(MutationDispatchError::Errno(libc::EROFS))
        ));
        assert!(matches!(
            fuse.dispatch_mkdir(1, OsStr::new("d"), 0o755, 1, 1),
            Err(MutationDispatchError::Errno(libc::EROFS))
        ));
        assert!(matches!(
            fuse.dispatch_rmdir(1, OsStr::new("d")),
            Err(MutationDispatchError::Errno(libc::EROFS))
        ));
        assert!(matches!(
            fuse.dispatch_rename(1, OsStr::new("a"), 2, OsStr::new("b")),
            Err(MutationDispatchError::Errno(libc::EROFS))
        ));
        assert!(calls.lock().expect("lock calls").is_empty());
    }

    #[test]
    fn dispatch_write_returns_ebusy_under_emergency_backpressure() {
        use asupersync::SystemPressure;
        use ffs_core::DegradationFsm;

        let calls = Arc::new(Mutex::new(Vec::new()));
        let options = MountOptions {
            read_only: false,
            ..MountOptions::default()
        };
        let pressure = Arc::new(SystemPressure::with_headroom(0.02));
        let fsm = Arc::new(DegradationFsm::new(Arc::clone(&pressure), 1));
        fsm.tick();
        let gate = BackpressureGate::new(fsm);
        let fuse = FrankenFuse::with_backpressure(
            Box::new(MutationRecordingFs::new(Arc::clone(&calls))),
            &options,
            gate,
        );

        let err = fuse
            .dispatch_write(11, 0, b"abc")
            .expect_err("write should be shed");
        assert!(matches!(err, MutationDispatchError::Errno(libc::EBUSY)));
        assert!(calls.lock().expect("lock calls").is_empty());
    }

    #[test]
    fn fuse_error_context_returns_correct_errno() {
        let cases: Vec<(FfsError, libc::c_int)> = vec![
            (FfsError::NotFound("test".into()), libc::ENOENT),
            (FfsError::PermissionDenied, libc::EACCES),
            (FfsError::IsDirectory, libc::EISDIR),
            (FfsError::NotDirectory, libc::ENOTDIR),
            (FfsError::ReadOnly, libc::EROFS),
            (FfsError::NoSpace, libc::ENOSPC),
            (FfsError::NameTooLong, libc::ENAMETOOLONG),
            (FfsError::NotEmpty, libc::ENOTEMPTY),
            (FfsError::Exists, libc::EEXIST),
            (FfsError::Cancelled, libc::EINTR),
            (FfsError::MvccConflict { tx: 1, block: 2 }, libc::EAGAIN),
            (
                FfsError::Corruption {
                    block: 0,
                    detail: "bad csum".into(),
                },
                libc::EIO,
            ),
            (FfsError::Format("bad".into()), libc::EINVAL),
            (
                FfsError::UnsupportedFeature("ENCRYPT".into()),
                libc::EOPNOTSUPP,
            ),
            (FfsError::RepairFailed("irrecoverable".into()), libc::EIO),
        ];

        for (error, expected) in &cases {
            let ctx = FuseErrorContext {
                error,
                operation: "test_op",
                ino: 42,
                offset: None,
            };
            assert_eq!(ctx.log_and_errno(), *expected, "wrong errno for {error:?}");
        }
    }

    #[test]
    fn fuse_error_context_with_offset() {
        let error = FfsError::NotFound("file.txt".into());
        let ctx = FuseErrorContext {
            error: &error,
            operation: "read",
            ino: 100,
            offset: Some(4096),
        };
        assert_eq!(ctx.log_and_errno(), libc::ENOENT);
    }

    // ── Thread safety tests ──────────────────────────────────────────────

    #[test]
    fn franken_fuse_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<FrankenFuse>();
        assert_send_sync::<FuseInner>();
        assert_send_sync::<AtomicMetrics>();
    }

    #[test]
    fn mount_options_resolved_thread_count() {
        let mut opts = MountOptions::default();
        assert_eq!(opts.worker_threads, 0);
        // Auto resolution gives at least 1.
        assert!(opts.resolved_thread_count() >= 1);
        assert!(opts.resolved_thread_count() <= 8);

        opts.worker_threads = 4;
        assert_eq!(opts.resolved_thread_count(), 4);
    }

    #[test]
    fn franken_fuse_with_options_sets_thread_count() {
        let opts = MountOptions {
            worker_threads: 6,
            ..MountOptions::default()
        };
        let fuse = FrankenFuse::with_options(Box::new(StubFs), &opts);
        assert_eq!(fuse.thread_count(), 6);
    }

    #[test]
    fn atomic_metrics_snapshot_initially_zero() {
        let m = AtomicMetrics::new();
        let s = m.snapshot();
        assert_eq!(s.requests_total, 0);
        assert_eq!(s.requests_ok, 0);
        assert_eq!(s.requests_err, 0);
        assert_eq!(s.bytes_read, 0);
    }

    #[test]
    fn atomic_metrics_record_ok_and_err() {
        let m = AtomicMetrics::new();
        m.record_ok();
        m.record_ok();
        m.record_err();
        m.record_bytes_read(1024);
        let s = m.snapshot();
        assert_eq!(s.requests_total, 3);
        assert_eq!(s.requests_ok, 2);
        assert_eq!(s.requests_err, 1);
        assert_eq!(s.bytes_read, 1024);
    }

    #[test]
    fn cache_line_padded_alignment() {
        let padded = CacheLinePadded(AtomicU64::new(0));
        let ptr = std::ptr::addr_of!(padded) as usize;
        // Must be 64-byte aligned.
        assert_eq!(ptr % 64, 0);
    }

    #[test]
    fn request_scope_updates_metrics() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let fs = HookFs::new(Arc::clone(&events), false, false);
        let fuse = FrankenFuse::new(Box::new(fs));
        let cx = Cx::for_testing();

        // Successful request.
        let _ = fuse.with_request_scope(&cx, RequestOp::Read, |_cx, _scope| Ok::<u32, FfsError>(7));

        let s = fuse.metrics().snapshot();
        assert_eq!(s.requests_total, 1);
        assert_eq!(s.requests_ok, 1);
        assert_eq!(s.requests_err, 0);
    }

    #[test]
    fn request_scope_records_err_metric() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let fs = HookFs::new(Arc::clone(&events), false, false);
        let fuse = FrankenFuse::new(Box::new(fs));
        let cx = Cx::for_testing();

        let _ = fuse.with_request_scope(&cx, RequestOp::Read, |_cx, _scope| {
            Err::<u32, FfsError>(FfsError::NotFound("gone".into()))
        });

        let s = fuse.metrics().snapshot();
        assert_eq!(s.requests_total, 1);
        assert_eq!(s.requests_ok, 0);
        assert_eq!(s.requests_err, 1);
    }

    #[test]
    fn concurrent_fsops_access_no_deadlock() {
        // Verify FsOps can be called concurrently from multiple threads
        // via Arc<dyn FsOps>.
        let fs: Arc<dyn FsOps> = Arc::new(StubFs);
        let barrier = Arc::new(std::sync::Barrier::new(10));

        std::thread::scope(|s| {
            for _ in 0..10 {
                let fs: Arc<dyn FsOps> = Arc::clone(&fs);
                let barrier = Arc::clone(&barrier);
                s.spawn(move || {
                    let cx = Cx::for_testing();
                    barrier.wait();
                    for _ in 0..100 {
                        let _ = fs.getattr(&cx, &mut RequestScope::empty(), InodeNumber(1));
                        let _ = fs.readdir(&cx, &mut RequestScope::empty(), InodeNumber(1), 0);
                        let _ = fs.read(&cx, &mut RequestScope::empty(), InodeNumber(1), 0, 4096);
                    }
                });
            }
        });
    }

    #[test]
    fn concurrent_metrics_stress() {
        // 10 threads x 1000 increments each.
        let metrics = Arc::new(AtomicMetrics::new());
        let barrier = Arc::new(std::sync::Barrier::new(10));

        std::thread::scope(|s| {
            for _ in 0..10 {
                let m = Arc::clone(&metrics);
                let b = Arc::clone(&barrier);
                s.spawn(move || {
                    b.wait();
                    for _ in 0..1000 {
                        m.record_ok();
                        m.record_bytes_read(512);
                    }
                });
            }
        });

        let s = metrics.snapshot();
        assert_eq!(s.requests_total, 10_000);
        assert_eq!(s.requests_ok, 10_000);
        assert_eq!(s.requests_err, 0);
        assert_eq!(s.bytes_read, 10_000 * 512);
    }

    #[test]
    fn fuse_inner_shared_across_threads() {
        // Simulate multi-threaded FUSE dispatch: multiple threads share
        // the same FuseInner via Arc and call FsOps concurrently.
        let inner = Arc::new(FuseInner {
            ops: Arc::new(StubFs),
            metrics: Arc::new(AtomicMetrics::new()),
            thread_count: 4,
            read_only: true,
            ioctl_trace: None,
            backpressure: None,
            access_predictor: AccessPredictor::default(),
            readahead: ReadaheadManager::new(MAX_PENDING_READAHEAD_ENTRIES),
        });
        let barrier = Arc::new(std::sync::Barrier::new(10));

        std::thread::scope(|s| {
            for _ in 0..10 {
                let inner = Arc::clone(&inner);
                let barrier = Arc::clone(&barrier);
                s.spawn(move || {
                    let cx = Cx::for_testing();
                    barrier.wait();
                    for _ in 0..1000 {
                        let _ = inner
                            .ops
                            .getattr(&cx, &mut RequestScope::empty(), InodeNumber(2));
                        inner.metrics.record_ok();
                        let _ = inner.ops.read(
                            &cx,
                            &mut RequestScope::empty(),
                            InodeNumber(2),
                            0,
                            4096,
                        );
                        inner.metrics.record_bytes_read(4096);
                    }
                });
            }
        });

        let snap = inner.metrics.snapshot();
        assert_eq!(snap.requests_ok, 10_000);
        assert_eq!(snap.bytes_read, 10_000 * 4096);
    }

    // ── Mount lifecycle tests ─────────────────────────────────────────

    #[test]
    fn mount_config_default_has_30s_timeout() {
        let cfg = MountConfig::default();
        assert_eq!(cfg.unmount_timeout, Duration::from_secs(30));
        assert!(cfg.options.read_only);
    }

    #[test]
    fn mount_managed_rejects_empty_mountpoint() {
        let ops: Box<dyn FsOps> = Box::new(StubFs);
        let err = mount_managed(ops, "", &MountConfig::default()).unwrap_err();
        assert!(
            err.to_string().contains("empty"),
            "expected 'empty' in error: {err}"
        );
    }

    #[test]
    fn mount_managed_rejects_nonexistent_mountpoint() {
        let ops: Box<dyn FsOps> = Box::new(StubFs);
        let err = mount_managed(
            ops,
            "/tmp/frankenfs_no_such_dir_xyzzy",
            &MountConfig::default(),
        )
        .unwrap_err();
        assert!(
            err.to_string().contains("does not exist"),
            "expected 'does not exist' in error: {err}"
        );
    }

    #[test]
    fn mount_managed_rejects_file_mountpoint() {
        let file_path = existing_file_mountpoint();
        let ops: Box<dyn FsOps> = Box::new(StubFs);
        let err = mount_managed(ops, &file_path, &MountConfig::default()).unwrap_err();
        let err_text = err.to_string();
        assert!(
            err_text.contains("not a directory"),
            "expected 'not a directory' in error: {err_text}"
        );
    }

    #[test]
    fn mount_handle_shutdown_flag_lifecycle() {
        // Build a MountHandle manually (without a real FUSE session) to
        // exercise the shutdown flag + metrics plumbing.
        let metrics = Arc::new(AtomicMetrics::new());
        metrics.record_ok();
        metrics.record_ok();
        metrics.record_bytes_read(8192);

        let handle = MountHandle {
            session: None,
            mountpoint: PathBuf::from("/mnt/test"),
            shutdown: Arc::new(AtomicBool::new(false)),
            metrics: Arc::clone(&metrics),
            config: MountConfig::default(),
        };

        // Shutdown flag starts false.
        assert!(!handle.shutdown_flag().load(Ordering::Relaxed));

        // Metrics snapshot reflects pre-recorded data.
        let snap = handle.metrics_snapshot();
        assert_eq!(snap.requests_ok, 2);
        assert_eq!(snap.bytes_read, 8192);

        // Unmount returns final snapshot.
        let final_snap = handle.unmount();
        assert_eq!(final_snap.requests_ok, 2);
    }

    #[test]
    fn mount_handle_debug_format() {
        const MOUNT_HANDLE_DEBUG_GOLDEN: &str = concat!(
            "MountHandle { ",
            "mountpoint: \"/mnt/dbg\", ",
            "active: false, ",
            "shutdown: false, ",
            "metrics: MetricsSnapshot { requests_total: 0, requests_ok: 0, requests_err: 0, ",
            "bytes_read: 0, requests_throttled: 0, requests_shed: 0 }, ",
            "unmount_timeout: 30s }"
        );

        let handle = MountHandle {
            session: None,
            mountpoint: PathBuf::from("/mnt/dbg"),
            shutdown: Arc::new(AtomicBool::new(false)),
            metrics: Arc::new(AtomicMetrics::new()),
            config: MountConfig::default(),
        };
        let dbg = format!("{handle:?}");
        assert_eq!(dbg, MOUNT_HANDLE_DEBUG_GOLDEN);
    }

    #[test]
    fn mount_handle_drop_is_safe_without_session() {
        // Verify that dropping a MountHandle with no session doesn't panic.
        let handle = MountHandle {
            session: None,
            mountpoint: PathBuf::from("/mnt/drop"),
            shutdown: Arc::new(AtomicBool::new(false)),
            metrics: Arc::new(AtomicMetrics::new()),
            config: MountConfig::default(),
        };
        drop(handle);
    }

    #[test]
    fn mount_handle_wait_returns_on_shutdown() {
        let metrics = Arc::new(AtomicMetrics::new());
        metrics.record_ok();

        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_trigger = Arc::clone(&shutdown);

        let handle = MountHandle {
            session: None,
            mountpoint: PathBuf::from("/mnt/wait"),
            shutdown: Arc::clone(&shutdown),
            metrics,
            config: MountConfig::default(),
        };

        // Set the shutdown flag from another thread after a short delay.
        let shutdown_thread = std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            shutdown_trigger.store(true, Ordering::Relaxed);
        });

        let snap = handle.wait();
        shutdown_thread
            .join()
            .expect("shutdown trigger thread should not panic");
        assert_eq!(snap.requests_ok, 1);
    }

    #[test]
    fn mount_handle_wait_respects_unmount_timeout() {
        let config = MountConfig {
            options: MountOptions::default(),
            unmount_timeout: Duration::from_millis(60),
        };
        let shutdown = Arc::new(AtomicBool::new(false));
        let shutdown_trigger = Arc::clone(&shutdown);

        let handle = MountHandle {
            session: None,
            mountpoint: PathBuf::from("/mnt/timeout"),
            shutdown: Arc::clone(&shutdown),
            metrics: Arc::new(AtomicMetrics::new()),
            config: config.clone(),
        };

        // Set the shutdown flag after a delay. Since session is None,
        // do_unmount will exit immediately. We just want to ensure it doesn't hang.
        let shutdown_thread = std::thread::spawn(move || {
            std::thread::sleep(config.unmount_timeout);
            shutdown_trigger.store(true, Ordering::Relaxed);
        });

        let started = Instant::now();
        let snap = handle.wait();
        let elapsed = started.elapsed();

        shutdown_thread.join().unwrap();

        assert_eq!(snap.requests_total, 0);
        assert!(elapsed >= config.unmount_timeout);
        assert!(elapsed < Duration::from_millis(500));
    }

    // ── FuseErrorContext errno mapping for all 21 variants (bd-2s4.6) ──

    #[test]
    fn fuse_error_context_log_and_errno_covers_all_variants() {
        let cases: Vec<(FfsError, libc::c_int)> = vec![
            (FfsError::Io(std::io::Error::other("test")), libc::EIO),
            (
                FfsError::Corruption {
                    block: 1,
                    detail: "bad crc".into(),
                },
                libc::EIO,
            ),
            (FfsError::Format("bad magic".into()), libc::EINVAL),
            (FfsError::Parse("truncated".into()), libc::EINVAL),
            (
                FfsError::UnsupportedFeature("ENCRYPT".into()),
                libc::EOPNOTSUPP,
            ),
            (
                FfsError::IncompatibleFeature("missing FILETYPE".into()),
                libc::EOPNOTSUPP,
            ),
            (
                FfsError::UnsupportedBlockSize("8192".into()),
                libc::EOPNOTSUPP,
            ),
            (
                FfsError::InvalidGeometry("blocks_per_group=0".into()),
                libc::EINVAL,
            ),
            (FfsError::MvccConflict { tx: 1, block: 2 }, libc::EAGAIN),
            (FfsError::Cancelled, libc::EINTR),
            (FfsError::NoSpace, libc::ENOSPC),
            (FfsError::NotFound("gone".into()), libc::ENOENT),
            (FfsError::PermissionDenied, libc::EACCES),
            (FfsError::ReadOnly, libc::EROFS),
            (FfsError::NotDirectory, libc::ENOTDIR),
            (FfsError::IsDirectory, libc::EISDIR),
            (FfsError::NotEmpty, libc::ENOTEMPTY),
            (FfsError::NameTooLong, libc::ENAMETOOLONG),
            (FfsError::Exists, libc::EEXIST),
            (FfsError::RepairFailed("checksum".into()), libc::EIO),
        ];

        // 20 variants listed; verify count matches expectation.
        assert_eq!(
            cases.len(),
            20,
            "expected all 20 constructible FfsError variants"
        );

        for (error, expected) in &cases {
            let ctx = FuseErrorContext {
                error,
                operation: "test_op",
                ino: 99,
                offset: Some(0),
            };
            assert_eq!(ctx.log_and_errno(), *expected, "wrong errno for {error:?}");
        }
    }

    #[test]
    fn fuse_error_context_io_preserves_raw_os_error() {
        let raw = std::io::Error::from_raw_os_error(libc::EPERM);
        let err = FfsError::Io(raw);
        let ctx = FuseErrorContext {
            error: &err,
            operation: "open",
            ino: 5,
            offset: None,
        };
        assert_eq!(ctx.log_and_errno(), libc::EPERM);
    }

    #[test]
    fn fuse_error_context_enoent_does_not_panic() {
        // ENOENT is logged at trace, not warn — ensure it doesn't panic.
        let err = FfsError::NotFound("test".into());
        let ctx = FuseErrorContext {
            error: &err,
            operation: "lookup",
            ino: 2,
            offset: None,
        };
        assert_eq!(ctx.log_and_errno(), libc::ENOENT);
    }

    // ── Read-only flag propagation ───────────────────────────────────────

    #[test]
    fn fuse_inner_read_only_true_when_mount_option_set() {
        let opts = MountOptions {
            read_only: true,
            ..Default::default()
        };
        let fuse = FrankenFuse::with_options(Box::new(StubFs), &opts);
        assert!(fuse.inner.read_only);
    }

    #[test]
    fn fuse_inner_read_only_false_when_writable() {
        let opts = MountOptions {
            read_only: false,
            ..Default::default()
        };
        let fuse = FrankenFuse::with_options(Box::new(StubFs), &opts);
        assert!(!fuse.inner.read_only);
    }

    #[test]
    fn build_mount_options_omits_ro_when_read_write() {
        let opts = MountOptions {
            read_only: false,
            allow_other: false,
            auto_unmount: true,
            ioctl_trace_path: None,
            worker_threads: 0,
        };
        let mount_opts = build_mount_options(&opts);
        // Should NOT contain RO
        let has_ro = mount_opts.iter().any(|o| matches!(o, MountOption::RO));
        assert!(!has_ro, "RO should not be present when read_only=false");
    }

    #[test]
    fn build_mount_options_includes_allow_other_when_set() {
        let opts = MountOptions {
            read_only: true,
            allow_other: true,
            auto_unmount: false,
            ioctl_trace_path: None,
            worker_threads: 0,
        };
        let mount_opts = build_mount_options(&opts);
        let has_allow = mount_opts
            .iter()
            .any(|o| matches!(o, MountOption::AllowOther));
        assert!(has_allow, "AllowOther should be present");
    }

    #[test]
    fn build_mount_options_includes_queue_tuning_when_worker_threads_explicit() {
        let opts = MountOptions {
            read_only: true,
            allow_other: false,
            auto_unmount: true,
            ioctl_trace_path: None,
            worker_threads: 8,
        };
        let mount_opts = build_mount_options(&opts);
        assert!(
            mount_opts
                .iter()
                .any(|o| matches!(o, MountOption::CUSTOM(v) if v == "max_background=8"))
        );
        assert!(
            mount_opts
                .iter()
                .any(|o| matches!(o, MountOption::CUSTOM(v) if v == "congestion_threshold=6"))
        );
    }

    #[test]
    fn build_mount_options_auto_worker_threads_omits_queue_tuning() {
        let opts = MountOptions {
            read_only: true,
            allow_other: false,
            auto_unmount: true,
            ioctl_trace_path: None,
            worker_threads: 0,
        };
        let mount_opts = build_mount_options(&opts);
        assert!(
            !mount_opts
                .iter()
                .any(|o| matches!(o, MountOption::CUSTOM(v) if v.starts_with("max_background=")))
        );
        assert!(!mount_opts.iter().any(
            |o| matches!(o, MountOption::CUSTOM(v) if v.starts_with("congestion_threshold="))
        ));
    }

    #[test]
    fn build_mount_options_excludes_kernel_writeback_cache_mode() {
        let opts = MountOptions::default();
        let mount_opts = build_mount_options(&opts);
        assert!(
            !mount_opts.iter().any(
                |option| matches!(option, MountOption::CUSTOM(v) if v.contains("writeback_cache"))
            ),
            "writeback_cache should remain disabled in V1 mount options: {mount_opts:?}"
        );
        let debug_dump = format!("{mount_opts:?}").to_ascii_lowercase();
        assert!(
            !debug_dump.contains("writebackcache"),
            "unexpected WritebackCache-like option in mount options: {mount_opts:?}"
        );
    }

    // ── should_shed backpressure tests ───────────────────────────────────

    #[test]
    fn should_shed_returns_false_without_backpressure_gate() {
        let fuse = FrankenFuse::new(Box::new(StubFs));
        // No backpressure gate → never shed.
        assert!(!fuse.should_shed(RequestOp::Read));
        assert!(!fuse.should_shed(RequestOp::Write));
        assert!(!fuse.should_shed(RequestOp::Create));
        assert!(!fuse.should_shed(RequestOp::Mkdir));
    }

    #[test]
    fn should_shed_with_emergency_gate_sheds_writes() {
        use asupersync::SystemPressure;
        use ffs_core::DegradationFsm;

        // Emergency level: headroom 0.02 → all writes shed.
        let pressure = Arc::new(SystemPressure::with_headroom(0.02));
        let fsm = Arc::new(DegradationFsm::new(Arc::clone(&pressure), 1));
        fsm.tick();
        let gate = BackpressureGate::new(fsm);

        let opts = MountOptions::default();
        let fuse = FrankenFuse::with_backpressure(Box::new(StubFs), &opts, gate);

        // Reads proceed.
        assert!(!fuse.should_shed(RequestOp::Read));
        assert!(!fuse.should_shed(RequestOp::Lookup));
        assert!(!fuse.should_shed(RequestOp::Getattr));
        assert!(!fuse.should_shed(RequestOp::Readdir));

        // Writes are shed.
        assert!(fuse.should_shed(RequestOp::Write));
        assert!(fuse.should_shed(RequestOp::Create));
        assert!(fuse.should_shed(RequestOp::Mkdir));
        assert!(fuse.should_shed(RequestOp::Unlink));
        assert!(fuse.should_shed(RequestOp::Rmdir));
        assert!(fuse.should_shed(RequestOp::Rename));
        assert!(fuse.should_shed(RequestOp::Link));
        assert!(fuse.should_shed(RequestOp::Symlink));
        assert!(fuse.should_shed(RequestOp::Fallocate));
        assert!(fuse.should_shed(RequestOp::Setattr));
        assert!(fuse.should_shed(RequestOp::Setxattr));
        assert!(fuse.should_shed(RequestOp::Removexattr));
    }

    #[test]
    fn should_shed_with_normal_gate_proceeds_all() {
        use asupersync::SystemPressure;
        use ffs_core::DegradationFsm;

        // Normal level: headroom 0.9 → all ops proceed.
        let pressure = Arc::new(SystemPressure::with_headroom(0.9));
        let fsm = Arc::new(DegradationFsm::new(Arc::clone(&pressure), 1));
        fsm.tick();
        let gate = BackpressureGate::new(fsm);

        let opts = MountOptions::default();
        let fuse = FrankenFuse::with_backpressure(Box::new(StubFs), &opts, gate);

        assert!(!fuse.should_shed(RequestOp::Read));
        assert!(!fuse.should_shed(RequestOp::Write));
        assert!(!fuse.should_shed(RequestOp::Create));
        assert!(!fuse.should_shed(RequestOp::Mkdir));
    }

    #[test]
    fn should_shed_with_degraded_gate_throttles_without_shedding() {
        use asupersync::SystemPressure;
        use ffs_core::DegradationFsm;

        // Degraded level: headroom 0.2 -> writes are throttled (not shed).
        let pressure = Arc::new(SystemPressure::with_headroom(0.2));
        let fsm = Arc::new(DegradationFsm::new(Arc::clone(&pressure), 1));
        fsm.tick();
        let gate = BackpressureGate::new(fsm);

        let opts = MountOptions::default();
        let fuse = FrankenFuse::with_backpressure(Box::new(StubFs), &opts, gate);

        let start = std::time::Instant::now();
        assert!(!fuse.should_shed(RequestOp::Write));
        assert!(start.elapsed() >= BACKPRESSURE_THROTTLE_DELAY);
    }

    // ── AccessPredictor backward sequence detection ──────────────────────

    #[test]
    fn access_predictor_backward_sequence_does_not_batch() {
        let predictor = AccessPredictor::default();
        let ino = InodeNumber(20);
        let size = 4096_u32;

        // Read backward: 3*4096, 2*4096, 1*4096, 0
        predictor.record_read(ino, u64::from(size) * 3, size);
        predictor.record_read(ino, u64::from(size) * 2, size);
        predictor.record_read(ino, u64::from(size), size);

        // After backward sequence, fetch_size should NOT batch (returns requested).
        assert_eq!(predictor.fetch_size(ino, 0, size), size);
    }

    #[test]
    fn access_predictor_random_access_does_not_batch() {
        let predictor = AccessPredictor::default();
        let ino = InodeNumber(21);
        let size = 4096_u32;

        // Random offsets.
        predictor.record_read(ino, 0, size);
        predictor.record_read(ino, u64::from(size) * 10, size);
        predictor.record_read(ino, u64::from(size) * 3, size);
        predictor.record_read(ino, u64::from(size) * 7, size);

        // Not sequential → no batching.
        assert_eq!(predictor.fetch_size(ino, u64::from(size) * 8, size), size);
    }

    #[test]
    fn access_predictor_different_inodes_are_independent() {
        let predictor = AccessPredictor::default();
        let size = 4096_u32;

        // Build forward sequence on inode 30.
        for i in 0..5_u64 {
            predictor.record_read(InodeNumber(30), i * u64::from(size), size);
        }

        // Inode 31 has no history — should not batch.
        assert_eq!(predictor.fetch_size(InodeNumber(31), 0, size), size);
    }

    #[test]
    fn access_predictor_history_is_bounded() {
        let predictor = AccessPredictor::new(3);
        let size = 4096_u32;

        for ino in 0..10_u64 {
            predictor.record_read(InodeNumber(100 + ino), 0, size);
        }

        let tracked = {
            let guard = match predictor.state.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard.history.len()
        };
        assert_eq!(tracked, 3);
    }

    #[test]
    fn access_predictor_rebases_on_touch_overflow() {
        let predictor = AccessPredictor::new(3);
        let size = 4096_u32;

        {
            let mut guard = match predictor.state.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            guard.history.insert(
                1,
                AccessPattern {
                    last_offset: 0,
                    last_size: size,
                    sequential_count: 1,
                    direction: AccessDirection::Forward,
                    last_touch: u64::MAX - 1,
                },
            );
            guard.history.insert(
                2,
                AccessPattern {
                    last_offset: u64::from(size),
                    last_size: size,
                    sequential_count: 1,
                    direction: AccessDirection::Forward,
                    last_touch: u64::MAX,
                },
            );
            guard.lru.insert(u64::MAX - 1, 1);
            guard.lru.insert(u64::MAX, 2);
            guard.next_touch = u64::MAX;
        }

        predictor.record_read(InodeNumber(3), 0, size);

        let (history_len, lru_len, next_touch) = {
            let guard = match predictor.state.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            (guard.history.len(), guard.lru.len(), guard.next_touch)
        };

        assert_eq!(history_len, 3);
        assert_eq!(lru_len, 3);
        assert!(next_touch < u64::MAX);
    }

    #[test]
    fn access_predictor_evicts_least_recent_inode() {
        let predictor = AccessPredictor::new(2);
        let size = 4096_u32;

        predictor.record_read(InodeNumber(1), 0, size);
        predictor.record_read(InodeNumber(2), 0, size);
        predictor.record_read(InodeNumber(1), u64::from(size), size);
        predictor.record_read(InodeNumber(3), 0, size);

        let (tracked, has_one, has_two, has_three) = {
            let guard = match predictor.state.lock() {
                Ok(guard) => guard,
                Err(poisoned) => poisoned.into_inner(),
            };
            (
                guard.history.len(),
                guard.history.contains_key(&1),
                guard.history.contains_key(&2),
                guard.history.contains_key(&3),
            )
        };
        assert_eq!(tracked, 2);
        assert!(has_one);
        assert!(!has_two);
        assert!(has_three);
    }

    // ── Concurrent AccessPredictor stress ────────────────────────────────

    #[test]
    fn access_predictor_concurrent_stress() {
        let predictor = Arc::new(AccessPredictor::default());
        let barrier = Arc::new(std::sync::Barrier::new(8));

        std::thread::scope(|s| {
            for thread_id in 0_u64..8 {
                let predictor = Arc::clone(&predictor);
                let barrier = Arc::clone(&barrier);
                s.spawn(move || {
                    let ino = InodeNumber(100 + thread_id);
                    barrier.wait();
                    for i in 0_u64..500 {
                        let offset = i * 4096;
                        let _ = predictor.fetch_size(ino, offset, 4096);
                        predictor.record_read(ino, offset, 4096);
                    }
                });
            }
        });

        // No panic or deadlock = success. Verify state is queryable.
        for thread_id in 0_u64..8 {
            let _ = predictor.fetch_size(InodeNumber(100 + thread_id), 0, 4096);
        }
    }

    // ── Metrics record_err tracking ──────────────────────────────────────

    #[test]
    fn atomic_metrics_tracks_errors_separately() {
        let metrics = AtomicMetrics::new();
        metrics.record_ok();
        metrics.record_ok();
        metrics.record_err();
        metrics.record_bytes_read(1024);

        let snap = metrics.snapshot();
        assert_eq!(snap.requests_total, 3);
        assert_eq!(snap.requests_ok, 2);
        assert_eq!(snap.requests_err, 1);
        assert_eq!(snap.bytes_read, 1024);
    }

    // ── MountOptions thread count resolution ─────────────────────────────

    #[test]
    fn resolved_thread_count_auto_is_bounded() {
        let opts = MountOptions {
            worker_threads: 0,
            ..Default::default()
        };
        let count = opts.resolved_thread_count();
        assert!(count >= 1);
        assert!(count <= 8);
    }

    #[test]
    fn resolved_thread_count_explicit_value_passes_through() {
        let opts = MountOptions {
            worker_threads: 4,
            ..Default::default()
        };
        assert_eq!(opts.resolved_thread_count(), 4);
    }

    #[test]
    fn resolved_thread_count_clamps_to_at_least_one() {
        // worker_threads=0 means auto, so test with 1.
        let opts = MountOptions {
            worker_threads: 1,
            ..Default::default()
        };
        assert_eq!(opts.resolved_thread_count(), 1);
    }

    // ── FrankenFuse thread_count accessor ────────────────────────────────

    #[test]
    fn franken_fuse_thread_count_matches_options() {
        let opts = MountOptions {
            worker_threads: 3,
            ..Default::default()
        };
        let fuse = FrankenFuse::with_options(Box::new(StubFs), &opts);
        assert_eq!(fuse.thread_count(), 3);
    }

    // ── ReadaheadManager edge cases ──────────────────────────────────────

    #[test]
    fn readahead_manager_miss_returns_none() {
        let manager = ReadaheadManager::new(8);
        // No data inserted → take returns None.
        assert_eq!(manager.take(InodeNumber(1), 0, 4), None);
    }

    #[test]
    fn readahead_manager_wrong_offset_returns_none() {
        let manager = ReadaheadManager::new(8);
        let ino = InodeNumber(2);
        manager.insert(ino, 100, vec![1, 2, 3]);
        // Wrong offset → miss.
        assert_eq!(manager.take(ino, 200, 3), None);
        // Correct offset → hit.
        assert_eq!(manager.take(ino, 100, 3), Some(vec![1, 2, 3]));
    }

    #[test]
    fn readahead_manager_exact_size_take() {
        let manager = ReadaheadManager::new(8);
        let ino = InodeNumber(3);
        manager.insert(ino, 0, vec![10, 20, 30, 40]);
        // Take exactly the stored amount.
        assert_eq!(manager.take(ino, 0, 4), Some(vec![10, 20, 30, 40]));
        // Second take should return None (consumed).
        assert_eq!(manager.take(ino, 0, 4), None);
    }

    // ── Edge-case hardening tests ──────────────────────────────────────

    const REPRESENTATIVE_RW_ALLOW_OTHER_THREADS_MOUNT_OPTIONS_GOLDEN: &str = r#"FSName("frankenfs")
Subtype("ffs")
DefaultPermissions
NoAtime
AllowOther
CUSTOM("max_background=4")
CUSTOM("congestion_threshold=3")"#;

    fn mount_option_debug_lines(options: &[MountOption]) -> String {
        options
            .iter()
            .map(|option| format!("{option:?}"))
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn build_mount_options_rw_allow_other_with_threads() {
        let opts = MountOptions {
            read_only: false,
            allow_other: true,
            auto_unmount: false,
            ioctl_trace_path: None,
            worker_threads: 4,
        };
        let mount_opts = build_mount_options(&opts);
        let actual = mount_option_debug_lines(&mount_opts);
        assert_eq!(
            actual,
            REPRESENTATIVE_RW_ALLOW_OTHER_THREADS_MOUNT_OPTIONS_GOLDEN
        );
    }

    #[test]
    fn build_mount_options_zero_threads_omits_custom_background() {
        let opts = MountOptions {
            worker_threads: 0,
            ..MountOptions::default()
        };
        let mount_opts = build_mount_options(&opts);
        let dbg = format!("{mount_opts:?}");
        assert!(
            !dbg.contains("max_background"),
            "zero threads should not set max_background: {dbg}"
        );
    }

    #[test]
    fn metrics_snapshot_equality() {
        let a = MetricsSnapshot {
            requests_total: 10,
            requests_ok: 7,
            requests_err: 3,
            bytes_read: 4096,
            requests_throttled: 0,
            requests_shed: 0,
        };
        let b = a;
        assert_eq!(a, b);

        let c = MetricsSnapshot {
            requests_total: 10,
            requests_ok: 6,
            requests_err: 4,
            bytes_read: 4096,
            requests_throttled: 0,
            requests_shed: 0,
        };
        assert_ne!(a, c);
    }

    #[test]
    fn atomic_metrics_tracks_pressure_counters() {
        let m = AtomicMetrics::new();
        m.record_throttled();
        m.record_throttled();
        m.record_shed();
        let snap = m.snapshot();
        assert_eq!(snap.requests_throttled, 2);
        assert_eq!(snap.requests_shed, 1);
    }

    #[test]
    fn atomic_metrics_debug_shows_fields() {
        const ATOMIC_METRICS_DEBUG_GOLDEN: &str = concat!(
            "AtomicMetrics { ",
            "requests_total: 1, ",
            "requests_ok: 1, ",
            "requests_err: 0, ",
            "bytes_read: 512, ",
            "requests_throttled: 1, ",
            "requests_shed: 0",
            " }"
        );

        let m = AtomicMetrics::new();
        m.record_ok();
        m.record_bytes_read(512);
        m.record_throttled();
        let dbg = format!("{m:?}");
        assert_eq!(dbg, ATOMIC_METRICS_DEBUG_GOLDEN);
    }

    #[test]
    fn cache_line_padded_debug_delegates_to_inner() {
        const CACHE_LINE_PADDED_DEBUG_GOLDEN: &str = "42";

        let padded = CacheLinePadded(42_u32);
        let dbg = format!("{padded:?}");
        assert_eq!(dbg, CACHE_LINE_PADDED_DEBUG_GOLDEN);
    }

    #[test]
    fn access_predictor_backward_sequence_not_coalesced() {
        // Backward sequential reads should increment sequential_count
        // but NOT trigger coalescing (only forward does).
        let predictor = AccessPredictor::new(64);
        let ino = InodeNumber(50);
        let size = 4096_u32;

        // Read offsets: 3*4096, 2*4096, 1*4096, 0 (backward).
        for i in (0..4).rev() {
            predictor.record_read(ino, u64::from(size) * i, size);
        }
        // Asking for the next backward read shouldn't coalesce.
        // Since coalescing is only for forward, fetch_size should return `size`.
        let fetch = predictor.fetch_size(ino, 0, size);
        assert_eq!(
            fetch, size,
            "backward sequence should not trigger coalescing"
        );
    }

    #[test]
    fn access_predictor_capacity_one_evicts_oldest() {
        let predictor = AccessPredictor::new(1);
        let size = 4096_u32;

        // Record inode 1, then inode 2 → inode 1 should be evicted.
        predictor.record_read(InodeNumber(1), 0, size);
        predictor.record_read(InodeNumber(2), 0, size);

        // Inode 1 should be unknown now.
        assert_eq!(predictor.fetch_size(InodeNumber(1), 0, size), size);

        // Inode 2 is still known.
        {
            let state = predictor.state.lock().unwrap();
            assert!(state.history.contains_key(&2));
            assert!(!state.history.contains_key(&1));
            drop(state);
        }
    }

    #[test]
    fn access_predictor_non_sequential_resets_count() {
        let predictor = AccessPredictor::new(64);
        let ino = InodeNumber(77);
        let size = 4096_u32;

        // Build forward sequential: 0, 4096, 8192.
        predictor.record_read(ino, 0, size);
        predictor.record_read(ino, 4096, size);
        predictor.record_read(ino, 8192, size);

        // Random jump to offset 999999 → resets sequential count.
        predictor.record_read(ino, 999_999, size);

        // Next forward read from expected position shouldn't coalesce
        // because sequential_count was reset to 1.
        let fetch = predictor.fetch_size(ino, 999_999 + u64::from(size), size);
        assert_eq!(fetch, size, "jump should reset sequential count");
    }

    #[test]
    fn readahead_manager_overwrite_same_key() {
        let manager = ReadaheadManager::new(8);
        let ino = InodeNumber(10);

        // Insert at offset 0 with data [1,2,3].
        manager.insert(ino, 0, vec![1, 2, 3]);
        // Overwrite at same key with [4,5,6].
        manager.insert(ino, 0, vec![4, 5, 6]);

        // Should get the latest data.
        assert_eq!(manager.take(ino, 0, 3), Some(vec![4, 5, 6]));
    }

    #[test]
    fn readahead_manager_empty_insert_is_noop() {
        let manager = ReadaheadManager::new(8);
        let ino = InodeNumber(20);

        manager.insert(ino, 0, vec![]);
        assert_eq!(manager.take(ino, 0, 0), None);
    }

    #[test]
    fn fuse_error_display_variants() {
        const INVALID_MOUNTPOINT_DISPLAY_GOLDEN: &str = "invalid mountpoint: bad path";
        const IO_ERROR_DISPLAY_GOLDEN: &str = "mount I/O error: disk gone";

        let invalid_mp = FuseError::InvalidMountpoint("bad path".into());
        assert_eq!(invalid_mp.to_string(), INVALID_MOUNTPOINT_DISPLAY_GOLDEN);

        let io_err = FuseError::Io(std::io::Error::other("disk gone"));
        assert_eq!(io_err.to_string(), IO_ERROR_DISPLAY_GOLDEN);
    }

    #[test]
    fn fuse_inner_debug_shows_non_exhaustive() {
        const FUSE_INNER_DEBUG_GOLDEN: &str = concat!(
            "FuseInner { ",
            "metrics: AtomicMetrics { requests_total: 0, requests_ok: 0, requests_err: 0, ",
            "bytes_read: 0, requests_throttled: 0, requests_shed: 0 }, ",
            "thread_count: 2, ",
            "read_only: false, ",
            ".. }"
        );

        let inner = FuseInner {
            ops: Arc::new(StubFs),
            metrics: Arc::new(AtomicMetrics::new()),
            thread_count: 2,
            read_only: false,
            ioctl_trace: None,
            backpressure: None,
            access_predictor: AccessPredictor::default(),
            readahead: ReadaheadManager::new(8),
        };
        let dbg = format!("{inner:?}");
        assert_eq!(dbg, FUSE_INNER_DEBUG_GOLDEN);
    }

    #[test]
    fn mount_options_worker_threads_one_resolves_to_one() {
        let opts = MountOptions {
            worker_threads: 1,
            ..MountOptions::default()
        };
        assert_eq!(opts.resolved_thread_count(), 1);
    }

    #[test]
    fn classify_xattr_reply_data_exact_fit() {
        // payload_len == size → Data.
        assert_eq!(
            FrankenFuse::classify_xattr_reply(32, 32),
            XattrReplyPlan::Data
        );
    }

    #[test]
    fn classify_xattr_reply_size_zero_payload() {
        // size=0, payload=0 → Size(0).
        assert_eq!(
            FrankenFuse::classify_xattr_reply(0, 0),
            XattrReplyPlan::Size(0)
        );
    }

    #[test]
    fn access_direction_equality() {
        assert_eq!(AccessDirection::Forward, AccessDirection::Forward);
        assert_eq!(AccessDirection::Backward, AccessDirection::Backward);
        assert_ne!(AccessDirection::Forward, AccessDirection::Backward);
    }

    // ── Mount runtime benchmark scenario tests (bd-h6nz.2.5) ──────────

    #[test]
    fn benchmark_per_core_dispatch_routing_is_deterministic() {
        use crate::per_core::{PerCoreConfig, PerCoreDispatcher};

        let config = PerCoreConfig {
            num_cores: 8,
            ..PerCoreConfig::default()
        };
        let d = PerCoreDispatcher::new(config);

        // Same inode always routes to same core.
        let core_a = d.route_inode(42);
        let core_b = d.route_inode(42);
        assert_eq!(core_a, core_b);
        assert!(core_a < 8);

        // Same parent always routes to same core for lookup.
        let lk_a = d.route_lookup(42);
        let lk_b = d.route_lookup(42);
        assert_eq!(lk_a, lk_b);
        assert!(lk_a < 8);
    }

    #[test]
    fn benchmark_per_core_aggregate_metrics_zero_when_idle() {
        use crate::per_core::{PerCoreConfig, PerCoreDispatcher};

        let d = PerCoreDispatcher::new(PerCoreConfig {
            num_cores: 4,
            ..PerCoreConfig::default()
        });
        let agg = d.aggregate_metrics();
        assert_eq!(agg.total_requests, 0);
        assert_eq!(agg.total_cache_hits, 0);
        assert_eq!(agg.total_cache_misses, 0);
        assert!((agg.aggregate_hit_rate - 0.0).abs() < f64::EPSILON);
        assert_eq!(agg.per_core.len(), 4);
    }

    #[test]
    fn benchmark_per_core_should_steal_false_when_balanced() {
        use crate::per_core::{PerCoreConfig, PerCoreDispatcher};

        let d = PerCoreDispatcher::new(PerCoreConfig {
            num_cores: 4,
            ..PerCoreConfig::default()
        });
        // Equal load on all cores.
        for core_id in 0..4_u32 {
            if let Some(m) = d.core_metrics(core_id) {
                for _ in 0..100 {
                    m.record_request();
                }
            }
        }
        // No core should want to steal when balanced.
        for core_id in 0..4_u32 {
            assert!(
                !d.should_steal(core_id),
                "core {core_id} should not steal when balanced"
            );
        }
    }

    #[test]
    fn benchmark_backpressure_decision_normal_never_sheds() {
        use asupersync::SystemPressure;
        use ffs_core::{BackpressureGate, DegradationFsm, RequestOp};

        let pressure = Arc::new(SystemPressure::new());
        let fsm = Arc::new(DegradationFsm::new(Arc::clone(&pressure), 1));
        let gate = BackpressureGate::new(fsm);

        // Normal pressure: neither reads nor writes are shed.
        assert_eq!(gate.check(RequestOp::Read), BackpressureDecision::Proceed);
        assert_eq!(gate.check(RequestOp::Write), BackpressureDecision::Proceed);
    }

    #[test]
    fn benchmark_backpressure_decision_emergency_sheds_writes() {
        use asupersync::SystemPressure;
        use ffs_core::{BackpressureGate, DegradationFsm, RequestOp};

        let pressure = Arc::new(SystemPressure::with_headroom(0.02));
        let fsm = Arc::new(DegradationFsm::new(Arc::clone(&pressure), 1));
        fsm.tick();
        let gate = BackpressureGate::new(fsm);

        // Emergency: reads proceed, writes shed.
        assert_eq!(gate.check(RequestOp::Read), BackpressureDecision::Proceed);
        assert_eq!(gate.check(RequestOp::Write), BackpressureDecision::Shed);
    }

    #[test]
    fn benchmark_metrics_snapshot_isolation() {
        // Snapshot must be a frozen copy — further writes don't affect it.
        let m = AtomicMetrics::new();
        m.record_ok();
        m.record_ok();
        let snap = m.snapshot();
        assert_eq!(snap.requests_total, 2);

        m.record_ok();
        // Original snapshot unchanged.
        assert_eq!(snap.requests_total, 2);
        // New snapshot reflects the third write.
        assert_eq!(m.snapshot().requests_total, 3);
    }

    // ── Degraded-mode pressure behavior tests (bd-h6nz.5.4) ──────────

    #[test]
    fn degraded_pressure_warning_does_not_affect_foreground() {
        use asupersync::SystemPressure;
        use ffs_core::{BackpressureGate, DegradationFsm, RequestOp};

        // Warning level: headroom 0.35 → no impact on foreground
        let pressure = Arc::new(SystemPressure::with_headroom(0.35));
        let fsm = Arc::new(DegradationFsm::new(Arc::clone(&pressure), 1));
        fsm.tick();
        let gate = BackpressureGate::new(fsm);

        // Both reads and writes should proceed at warning level.
        assert_eq!(gate.check(RequestOp::Read), BackpressureDecision::Proceed);
        assert_eq!(gate.check(RequestOp::Write), BackpressureDecision::Proceed);
        assert_eq!(gate.check(RequestOp::Create), BackpressureDecision::Proceed);
    }

    #[test]
    fn degraded_pressure_critical_throttles_writes_sheds_metadata() {
        use asupersync::SystemPressure;
        use ffs_core::{BackpressureGate, DegradationFsm, RequestOp};

        // Critical level: headroom 0.08
        let pressure = Arc::new(SystemPressure::with_headroom(0.08));
        let fsm = Arc::new(DegradationFsm::new(Arc::clone(&pressure), 1));
        fsm.tick();
        let gate = BackpressureGate::new(fsm);

        // Reads proceed.
        assert_eq!(gate.check(RequestOp::Read), BackpressureDecision::Proceed);
        // Writes throttled.
        assert_eq!(gate.check(RequestOp::Write), BackpressureDecision::Throttle);
        // Metadata writes (mkdir, unlink, etc.) are shed.
        assert_eq!(gate.check(RequestOp::Mkdir), BackpressureDecision::Shed);
        assert_eq!(gate.check(RequestOp::Unlink), BackpressureDecision::Shed);
    }

    #[test]
    fn degraded_pressure_fsm_tick_drives_transitions() {
        use asupersync::SystemPressure;
        use ffs_core::{DegradationFsm, DegradationLevel};

        let pressure = Arc::new(SystemPressure::new());
        let fsm = Arc::new(DegradationFsm::new(Arc::clone(&pressure), 1));

        // Starts at Normal.
        assert_eq!(fsm.level(), DegradationLevel::Normal);

        // Tick at normal headroom stays Normal.
        fsm.tick();
        assert_eq!(fsm.level(), DegradationLevel::Normal);
    }

    #[test]
    fn degraded_pressure_concurrent_checks_are_safe() {
        use asupersync::SystemPressure;
        use ffs_core::{BackpressureGate, DegradationFsm, RequestOp};

        let pressure = Arc::new(SystemPressure::new());
        let fsm = Arc::new(DegradationFsm::new(Arc::clone(&pressure), 1));
        let gate = Arc::new(BackpressureGate::new(fsm));

        // Run 4 threads hammering check() concurrently.
        std::thread::scope(|s| {
            for _ in 0..4 {
                let g = Arc::clone(&gate);
                s.spawn(move || {
                    for _ in 0..1000 {
                        let decision = g.check(RequestOp::Read);
                        assert_eq!(decision, BackpressureDecision::Proceed);
                    }
                });
            }
        });
    }

    #[test]
    fn degraded_pressure_escalation_order_is_monotonic() {
        use ffs_core::DegradationLevel;

        // Levels must be ordered Normal < Warning < Degraded < Critical < Emergency.
        assert!(DegradationLevel::Normal < DegradationLevel::Warning);
        assert!(DegradationLevel::Warning < DegradationLevel::Degraded);
        assert!(DegradationLevel::Degraded < DegradationLevel::Critical);
        assert!(DegradationLevel::Critical < DegradationLevel::Emergency);
    }

    // ── Proptest property-based tests ─────────────────────────────────────

    #[expect(clippy::cast_possible_truncation)] // test-only: proptest ranges guarantee safe casts
    mod proptests {
        use super::*;
        use crate::per_core::{
            CoreMetrics, PerCoreConfig, PerCoreDispatcher, inode_to_core, lookup_to_core,
        };
        use proptest::prelude::*;

        proptest! {
            #![proptest_config(ProptestConfig::with_cases(256))]

            // ── inode_to_core properties ────────────────────────────────

            /// Routing is always deterministic: same inputs produce same output.
            #[test]
            fn inode_routing_is_deterministic(ino in 0_u64..=u64::MAX, cores in 1_u32..=256) {
                let a = inode_to_core(ino, cores);
                let b = inode_to_core(ino, cores);
                prop_assert_eq!(a, b);
            }

            /// Routing output is always within [0, num_cores).
            #[test]
            fn inode_routing_in_range(ino in 0_u64..=u64::MAX, cores in 1_u32..=256) {
                let core = inode_to_core(ino, cores);
                prop_assert!(core < cores, "core {core} >= num_cores {cores}");
            }

            /// Routing with num_cores=0 always returns 0.
            #[test]
            fn inode_routing_zero_cores_always_zero(ino in 0_u64..=u64::MAX) {
                prop_assert_eq!(inode_to_core(ino, 0), 0);
            }

            /// With 1 core, every inode routes to core 0.
            #[test]
            fn inode_routing_single_core(ino in 0_u64..=u64::MAX) {
                prop_assert_eq!(inode_to_core(ino, 1), 0);
            }

            /// lookup_to_core delegates to inode_to_core on parent.
            #[test]
            fn lookup_routes_same_as_inode(parent in 0_u64..=u64::MAX, cores in 1_u32..=256) {
                prop_assert_eq!(
                    lookup_to_core(parent, cores),
                    inode_to_core(parent, cores)
                );
            }

            // ── classify_xattr_reply properties ────────────────────────

            /// size=0 always produces Size variant (probe mode).
            #[test]
            fn xattr_probe_always_returns_size(payload_len in 0_usize..=u32::MAX as usize) {
                let plan = FrankenFuse::classify_xattr_reply(0, payload_len);
                match plan {
                    XattrReplyPlan::Size(n) => {
                        prop_assert_eq!(n, u32::try_from(payload_len).unwrap());
                    }
                    _ => prop_assert!(false, "expected Size variant, got {plan:?}"),
                }
            }

            /// When buffer fits (payload <= size), always produces Data.
            #[test]
            fn xattr_data_when_fits(
                size in 1_u32..=u32::MAX,
                payload_len in 0_u32..=u32::MAX,
            ) {
                // Only test when payload_len <= size
                if payload_len <= size {
                    let plan = FrankenFuse::classify_xattr_reply(size, payload_len as usize);
                    prop_assert_eq!(plan, XattrReplyPlan::Data);
                }
            }

            /// When buffer too small (payload > size > 0), produces ERANGE.
            #[test]
            fn xattr_erange_when_too_small(
                size in 1_u32..=u32::MAX - 1,
                extra in 1_u32..=1024,
            ) {
                let payload_len = (u64::from(size) + u64::from(extra)).min(u64::from(u32::MAX)) as usize;
                if payload_len > usize::try_from(size).unwrap() {
                    let plan = FrankenFuse::classify_xattr_reply(size, payload_len);
                    prop_assert_eq!(plan, XattrReplyPlan::Error(libc::ERANGE));
                }
            }

            // ── parse_setxattr_mode properties ─────────────────────────

            /// Valid flags (0, CREATE, REPLACE) with position=0 always succeed.
            #[test]
            fn setxattr_valid_flags_succeed(flag in prop_oneof![
                Just(0_i32),
                Just(XATTR_FLAG_CREATE),
                Just(XATTR_FLAG_REPLACE),
            ]) {
                prop_assert!(FrankenFuse::parse_setxattr_mode(flag, 0).is_ok());
            }

            /// Non-zero position always fails with EINVAL.
            #[test]
            fn setxattr_nonzero_position_fails(flags in 0_i32..=3, position in 1_u32..=u32::MAX) {
                let result = FrankenFuse::parse_setxattr_mode(flags, position);
                prop_assert_eq!(result, Err(libc::EINVAL));
            }

            /// Unknown flags (bits outside CREATE|REPLACE) always fail.
            #[test]
            fn setxattr_unknown_flags_fail(unknown_bits in 4_i32..=i32::MAX) {
                // Ensure at least one bit outside the known mask is set.
                let known = XATTR_FLAG_CREATE | XATTR_FLAG_REPLACE;
                if unknown_bits & !known != 0 {
                    let result = FrankenFuse::parse_setxattr_mode(unknown_bits, 0);
                    prop_assert_eq!(result, Err(libc::EINVAL));
                }
            }

            /// CREATE|REPLACE together always fail.
            #[test]
            fn setxattr_create_and_replace_fail(_dummy in 0_u8..1) {
                let result = FrankenFuse::parse_setxattr_mode(
                    XATTR_FLAG_CREATE | XATTR_FLAG_REPLACE, 0
                );
                prop_assert_eq!(result, Err(libc::EINVAL));
            }

            // ── encode_xattr_names properties ──────────────────────────

            /// Encoded output length = sum(name.len() + 1) for each name.
            #[test]
            fn xattr_encode_length_property(
                names in prop::collection::vec("[a-z]{1,20}", 0..10)
            ) {
                let encoded = FrankenFuse::encode_xattr_names(&names);
                let expected_len: usize = names.iter().map(|n| n.len() + 1).sum();
                prop_assert_eq!(encoded.len(), expected_len);
            }

            /// Each encoded name ends with NUL separator.
            #[test]
            fn xattr_encode_nul_separated(
                names in prop::collection::vec("[a-z]{1,20}", 1..10)
            ) {
                let encoded = FrankenFuse::encode_xattr_names(&names);
                if !encoded.is_empty() {
                    prop_assert_eq!(*encoded.last().unwrap(), 0_u8);
                }
                // Count NUL bytes = number of names.
                #[expect(clippy::naive_bytecount)] // test: bytecount crate not warranted
                let nul_count = encoded.iter().filter(|&&b| b == 0).count();
                prop_assert_eq!(nul_count, names.len());
            }

            // ── AccessPredictor properties ──────────────────────────────

            /// History never exceeds max_entries.
            #[test]
            fn access_predictor_bounded_history(
                max_entries in 1_usize..=16,
                num_reads in 1_usize..=64,
            ) {
                let predictor = AccessPredictor::new(max_entries);
                for i in 0..u64::try_from(num_reads).unwrap() {
                    predictor.record_read(InodeNumber(i), 0, 4096);
                }
                let count = match predictor.state.lock() {
                    Ok(guard) => guard.history.len(),
                    Err(poisoned) => poisoned.into_inner().history.len(),
                };
                prop_assert!(count <= max_entries, "history {count} > max {max_entries}");
            }

            /// Fetch size for unknown inode equals requested size.
            #[test]
            fn access_predictor_unknown_inode_returns_requested(
                ino in 0_u64..=u64::MAX,
                offset in 0_u64..=u64::MAX,
                size in 1_u32..=65536,
            ) {
                let predictor = AccessPredictor::new(16);
                prop_assert_eq!(predictor.fetch_size(InodeNumber(ino), offset, size), size);
            }

            /// Zero-size reads are silently dropped (no state mutation).
            #[test]
            fn access_predictor_zero_size_read_is_noop(ino in 0_u64..=1000) {
                let predictor = AccessPredictor::new(16);
                predictor.record_read(InodeNumber(ino), 0, 0);
                let count = match predictor.state.lock() {
                    Ok(guard) => guard.history.len(),
                    Err(poisoned) => poisoned.into_inner().history.len(),
                };
                prop_assert_eq!(count, 0);
            }

            /// Coalesced fetch size is always >= requested size.
            #[test]
            fn access_predictor_fetch_at_least_requested(
                offset in 0_u64..=1_000_000,
                size in 1_u32..=65536,
            ) {
                let predictor = AccessPredictor::new(64);
                let ino = InodeNumber(42);
                // Build some sequential history.
                for i in 0..5_u64 {
                    predictor.record_read(ino, i * u64::from(size), size);
                }
                let fetch = predictor.fetch_size(ino, offset, size);
                prop_assert!(fetch >= size, "fetch {fetch} < requested {size}");
            }

            /// Coalesced fetch size never exceeds MAX_COALESCED_READ_SIZE.
            #[test]
            fn access_predictor_fetch_capped(size in 1_u32..=65536) {
                let predictor = AccessPredictor::new(64);
                let ino = InodeNumber(99);
                // Build long forward sequence.
                for i in 0..20_u64 {
                    predictor.record_read(ino, i * u64::from(size), size);
                }
                let next_offset = 20 * u64::from(size);
                let fetch = predictor.fetch_size(ino, next_offset, size);
                prop_assert!(
                    fetch <= MAX_COALESCED_READ_SIZE.max(size),
                    "fetch {fetch} > cap {}",
                    MAX_COALESCED_READ_SIZE.max(size)
                );
            }

            // ── ReadaheadManager properties ─────────────────────────────

            /// insert then take at same offset returns the data.
            #[test]
            fn readahead_insert_take_roundtrip(
                ino in 1_u64..=1000,
                offset in 0_u64..=1_000_000,
                data in prop::collection::vec(any::<u8>(), 1..128),
            ) {
                let manager = ReadaheadManager::new(64);
                let data_clone = data.clone();
                manager.insert(InodeNumber(ino), offset, data);
                let taken = manager.take(InodeNumber(ino), offset, data_clone.len());
                prop_assert_eq!(taken, Some(data_clone));
            }

            /// take after consume returns None.
            #[test]
            fn readahead_double_take_returns_none(
                ino in 1_u64..=1000,
                offset in 0_u64..=1_000_000,
                data in prop::collection::vec(any::<u8>(), 1..64),
            ) {
                let manager = ReadaheadManager::new(64);
                let len = data.len();
                manager.insert(InodeNumber(ino), offset, data);
                let _ = manager.take(InodeNumber(ino), offset, len);
                let second = manager.take(InodeNumber(ino), offset, len);
                prop_assert_eq!(second, None);
            }

            /// Pending entries never exceed max_pending.
            #[test]
            fn readahead_bounded_entries(
                max_pending in 1_usize..=8,
                num_inserts in 1_usize..=32,
            ) {
                let manager = ReadaheadManager::new(max_pending);
                for i in 0..u64::try_from(num_inserts).unwrap() {
                    manager.insert(InodeNumber(1), i * 1024, vec![0xAA]);
                }
                let count = match manager.pending.lock() {
                    Ok(guard) => guard.map.len(),
                    Err(poisoned) => poisoned.into_inner().map.len(),
                };
                prop_assert!(count <= max_pending, "entries {count} > max {max_pending}");
            }

            /// Empty data insertions are silently ignored.
            #[test]
            fn readahead_empty_insert_ignored(ino in 1_u64..=100, offset in 0_u64..=1000) {
                let manager = ReadaheadManager::new(8);
                manager.insert(InodeNumber(ino), offset, vec![]);
                let count = match manager.pending.lock() {
                    Ok(guard) => guard.map.len(),
                    Err(poisoned) => poisoned.into_inner().map.len(),
                };
                prop_assert_eq!(count, 0);
            }

            /// Partial take returns prefix and preserves tail at correct offset.
            #[test]
            fn readahead_partial_take_preserves_tail(
                data in prop::collection::vec(any::<u8>(), 4..128),
                take_len in 1_usize..=3,
            ) {
                let manager = ReadaheadManager::new(16);
                let ino = InodeNumber(7);
                let offset = 0_u64;
                let data_clone = data.clone();
                let actual_take = take_len.min(data.len() - 1); // Ensure a tail exists.
                if actual_take < data.len() {
                    manager.insert(ino, offset, data);
                    let prefix = manager.take(ino, offset, actual_take);
                    prop_assert_eq!(prefix.as_deref(), Some(&data_clone[..actual_take]));

                    // Tail should be at offset + actual_take.
                    let tail_offset = offset + u64::try_from(actual_take).unwrap();
                    let tail = manager.take(ino, tail_offset, data_clone.len());
                    prop_assert_eq!(tail.as_deref(), Some(&data_clone[actual_take..]));
                }
            }

            // ── AtomicMetrics properties ────────────────────────────────

            /// ok + err always equals total.
            #[test]
            fn metrics_ok_plus_err_equals_total(
                num_ok in 0_u64..=500,
                num_err in 0_u64..=500,
            ) {
                let metrics = AtomicMetrics::new();
                for _ in 0..num_ok { metrics.record_ok(); }
                for _ in 0..num_err { metrics.record_err(); }
                let snap = metrics.snapshot();
                prop_assert_eq!(snap.requests_ok, num_ok);
                prop_assert_eq!(snap.requests_err, num_err);
                prop_assert_eq!(snap.requests_total, num_ok + num_err);
            }

            /// bytes_read accumulates correctly.
            #[test]
            fn metrics_bytes_read_accumulates(
                reads in prop::collection::vec(1_u64..=8192, 0..50),
            ) {
                let metrics = AtomicMetrics::new();
                let expected: u64 = reads.iter().sum();
                for &n in &reads {
                    metrics.record_bytes_read(n);
                }
                prop_assert_eq!(metrics.snapshot().bytes_read, expected);
            }

            // ── MountOptions properties ─────────────────────────────────

            /// Resolved thread count is always >= 1.
            #[test]
            fn mount_options_resolved_at_least_one(threads in 0_usize..=256) {
                let opts = MountOptions {
                    worker_threads: threads,
                    ..Default::default()
                };
                prop_assert!(opts.resolved_thread_count() >= 1);
            }

            /// Explicit worker_threads passes through (when > 0).
            #[test]
            fn mount_options_explicit_passthrough(threads in 1_usize..=256) {
                let opts = MountOptions {
                    worker_threads: threads,
                    ..Default::default()
                };
                prop_assert_eq!(opts.resolved_thread_count(), threads);
            }

            // ── PerCoreConfig properties ────────────────────────────────

            /// total_cache_blocks = resolved_cores * cache_blocks_per_core.
            #[test]
            fn per_core_total_cache_blocks(
                cores in 1_u32..=16,
                blocks_per_core in 1_u32..=65536,
            ) {
                let cfg = PerCoreConfig {
                    num_cores: cores,
                    cache_blocks_per_core: blocks_per_core,
                    steal_threshold: 2.0,
                    advisory_affinity: true,
                };
                prop_assert_eq!(
                    cfg.total_cache_blocks(),
                    u64::from(cores) * u64::from(blocks_per_core)
                );
            }

            /// PerCoreDispatcher has exactly num_cores metrics slots.
            #[test]
            fn dispatcher_correct_num_metrics(cores in 1_u32..=16) {
                let cfg = PerCoreConfig {
                    num_cores: cores,
                    ..Default::default()
                };
                let disp = PerCoreDispatcher::new(cfg);
                prop_assert_eq!(disp.num_cores(), cores);
                for c in 0..cores {
                    prop_assert!(disp.core_metrics(c).is_some());
                }
                prop_assert!(disp.core_metrics(cores).is_none());
            }

            /// Aggregate total_requests = sum of per-core requests.
            #[test]
            fn dispatcher_aggregate_sums(
                per_core_counts in prop::collection::vec(0_u64..=1000, 2..=8),
            ) {
                let n = per_core_counts.len() as u32;
                let cfg = PerCoreConfig {
                    num_cores: n,
                    ..Default::default()
                };
                let disp = PerCoreDispatcher::new(cfg);
                let mut expected_total = 0_u64;
                for (i, &count) in per_core_counts.iter().enumerate() {
                    let m = disp.core_metrics(i as u32).unwrap();
                    for _ in 0..count {
                        m.begin_request();
                        m.record_request();
                    }
                    expected_total += count;
                }
                let agg = disp.aggregate_metrics();
                prop_assert_eq!(agg.total_requests, expected_total);
                prop_assert_eq!(agg.per_core.len(), n as usize);
            }

            /// Hit rate is in [0.0, 1.0] range.
            #[test]
            fn core_metrics_hit_rate_bounded(
                hits in 0_u64..=1000,
                misses in 0_u64..=1000,
            ) {
                let m = CoreMetrics::new();
                for _ in 0..hits { m.record_hit(); }
                for _ in 0..misses { m.record_miss(); }
                let rate = m.snapshot().hit_rate();
                prop_assert!((0.0..=1.0).contains(&rate), "hit_rate {rate} out of bounds");
            }

            /// Imbalance ratio >= 1.0 (or infinity if min is zero).
            #[test]
            fn dispatcher_imbalance_ratio_at_least_one(
                per_core_counts in prop::collection::vec(0_u64..=1000, 2..=8),
            ) {
                let n = per_core_counts.len() as u32;
                let cfg = PerCoreConfig {
                    num_cores: n,
                    ..Default::default()
                };
                let disp = PerCoreDispatcher::new(cfg);
                for (i, &count) in per_core_counts.iter().enumerate() {
                    let m = disp.core_metrics(i as u32).unwrap();
                    for _ in 0..count {
                        m.begin_request();
                        m.record_request();
                    }
                }
                let ratio = disp.aggregate_metrics().imbalance_ratio();
                prop_assert!(ratio >= 1.0 || ratio.is_infinite(),
                    "imbalance_ratio {ratio} < 1.0");
            }
        }
    }
}
