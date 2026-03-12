//! Append-only WAL writer with integrity checks, sync policy, and backpressure.
//!
//! This module provides [`WalWriter`], the write-path counterpart to the WAL
//! replay engine in [`crate::persist`].  It encodes commit records, appends
//! them atomically, optionally verifies the written data by reading back, and
//! manages durability boundaries according to a configurable [`SyncPolicy`].
//!
//! # Error Classification
//!
//! All write failures are returned as [`WalWriteError`], which distinguishes:
//!
//! - **Retryable** failures: I/O errors, backpressure — the caller may retry
//!   after addressing the underlying condition.
//! - **Fatal** failures: format violations, verification failures — these
//!   indicate a bug or unrecoverable state.
//!
//! # Invariants Enforced
//!
//! - **D1:** Commit sequence is strictly increasing (monotonicity).
//! - **D8:** Reserved sentinel values (`u64::MAX`) are rejected.
//! - Per-record CRC32C integrity (via [`crate::wal::encode_commit`]).

use crate::wal::{self, WalCommit, WalHeader, HEADER_SIZE};
use ffs_error::{FfsError, Result};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use tracing::{debug, error, info, warn};

// ── Error types ──────────────────────────────────────────────────────────────

/// Classified error for WAL write operations.
///
/// Each variant carries enough context to decide whether to retry, abort, or
/// escalate.  Use [`is_retryable`](WalWriteError::is_retryable) and
/// [`is_fatal`](WalWriteError::is_fatal) for programmatic triage.
#[derive(Debug)]
pub enum WalWriteError {
    /// I/O error during append — may be retryable (e.g. `ENOSPC`, `EINTR`).
    AppendIo {
        source: std::io::Error,
        bytes_attempted: usize,
    },
    /// I/O error during sync — data was appended but durability is not guaranteed.
    SyncIo { source: std::io::Error },
    /// Encoding or invariant violation — fatal, likely indicates a bug.
    FormatViolation { detail: String },
    /// Read-back verification failed: written data does not match expected CRC.
    VerificationFailed {
        expected_crc: u32,
        actual_crc: u32,
        offset: u64,
    },
    /// WAL size exceeds the configured backpressure threshold.
    Backpressure { wal_size: u64, threshold: u64 },
}

impl WalWriteError {
    /// Whether this error class is potentially retryable.
    #[must_use]
    pub fn is_retryable(&self) -> bool {
        matches!(self, Self::AppendIo { .. } | Self::Backpressure { .. })
    }

    /// Whether this error class is fatal (indicates a bug or unrecoverable state).
    #[must_use]
    pub fn is_fatal(&self) -> bool {
        matches!(
            self,
            Self::FormatViolation { .. } | Self::VerificationFailed { .. }
        )
    }
}

impl std::fmt::Display for WalWriteError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AppendIo {
                source,
                bytes_attempted,
            } => {
                write!(
                    f,
                    "WAL append I/O error ({bytes_attempted} bytes attempted): {source}"
                )
            }
            Self::SyncIo { source } => write!(f, "WAL sync I/O error: {source}"),
            Self::FormatViolation { detail } => write!(f, "WAL format violation: {detail}"),
            Self::VerificationFailed {
                expected_crc,
                actual_crc,
                offset,
            } => {
                write!(
                    f,
                    "WAL write verification failed at offset {offset}: \
                     expected CRC {expected_crc:#010x}, got {actual_crc:#010x}"
                )
            }
            Self::Backpressure {
                wal_size,
                threshold,
            } => {
                write!(
                    f,
                    "WAL backpressure: size {wal_size} exceeds threshold {threshold}"
                )
            }
        }
    }
}

impl std::error::Error for WalWriteError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::AppendIo { source, .. } | Self::SyncIo { source } => Some(source),
            _ => None,
        }
    }
}

impl From<WalWriteError> for FfsError {
    fn from(e: WalWriteError) -> Self {
        match e {
            WalWriteError::AppendIo { source, .. } | WalWriteError::SyncIo { source } => {
                FfsError::Io(source)
            }
            WalWriteError::FormatViolation { detail } => FfsError::Format(detail),
            WalWriteError::VerificationFailed {
                expected_crc,
                actual_crc,
                offset,
            } => FfsError::Corruption {
                block: 0,
                detail: format!(
                    "WAL write verification failed at offset {offset}: \
                     expected CRC {expected_crc:#010x}, got {actual_crc:#010x}"
                ),
            },
            WalWriteError::Backpressure {
                wal_size,
                threshold,
            } => FfsError::Format(format!(
                "WAL backpressure: size {wal_size} exceeds threshold {threshold}"
            )),
        }
    }
}

// ── Sync policy ──────────────────────────────────────────────────────────────

/// Policy governing when `fsync` is called after appending records.
///
/// | Policy | Durability window | Throughput |
/// |--------|-------------------|------------|
/// | `Immediate` | Zero (every record synced) | Lowest |
/// | `EveryN(n)` | Up to `n-1` records | Medium |
/// | `Manual` | Unbounded until caller flushes | Highest |
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncPolicy {
    /// Sync after every append (maximum durability, minimum throughput).
    Immediate,
    /// Sync after every `n` appends (trades durability window for throughput).
    EveryN(u32),
    /// Never auto-sync; caller manages durability via explicit [`WalWriter::flush`].
    Manual,
}

impl Default for SyncPolicy {
    fn default() -> Self {
        Self::Immediate
    }
}

// ── Writer configuration ─────────────────────────────────────────────────────

/// Configuration for the WAL writer.
#[derive(Debug, Clone)]
pub struct WalWriterConfig {
    /// Sync policy (default: `Immediate`).
    pub sync_policy: SyncPolicy,
    /// Verify writes by reading back and checking CRC (default: `false`).
    ///
    /// Enabling this adds one seek + read per append. Useful for paranoid
    /// durability or debugging, not recommended for hot paths.
    pub verify_writes: bool,
    /// WAL size threshold in bytes for backpressure signaling (0 = disabled).
    ///
    /// When the WAL reaches this size, [`WalWriter::append_commit`] returns
    /// [`WalWriteError::Backpressure`] instead of writing. The caller should
    /// checkpoint and compact before retrying.
    pub backpressure_threshold_bytes: u64,
}

impl Default for WalWriterConfig {
    fn default() -> Self {
        Self {
            sync_policy: SyncPolicy::Immediate,
            verify_writes: false,
            backpressure_threshold_bytes: 0,
        }
    }
}

// ── Append result ────────────────────────────────────────────────────────────

/// Result of a successful append operation.
#[derive(Debug, Clone, Copy)]
pub struct AppendResult {
    /// Byte offset where the record was written.
    pub offset: u64,
    /// Number of bytes written.
    pub bytes_written: u64,
    /// Whether the write was synced to disk.
    pub synced: bool,
    /// Number of pending (unsynced) appends after this write.
    pub pending_sync_count: u32,
}

// ── WalWriter ────────────────────────────────────────────────────────────────

/// Append-only WAL writer with integrity checks, sync policy, and backpressure.
///
/// Encodes [`WalCommit`] records, appends them at the current write position,
/// optionally verifies the written data, and manages durability boundaries.
///
/// # Thread safety
///
/// `WalWriter` is **not** `Sync`.  In [`crate::persist::PersistentMvccStore`],
/// it is wrapped in `RwLock<WalWriter>` so that only one writer can append at
/// a time while readers can query metadata concurrently.
#[derive(Debug)]
pub struct WalWriter {
    file: File,
    pub(crate) write_pos: u64,
    config: WalWriterConfig,
    /// Number of appends since the last sync.
    appends_since_sync: u32,
    /// Highest `commit_seq` successfully appended.
    last_commit_seq: u64,
    /// Monotonically increasing operation counter for structured logging.
    next_operation_id: u64,
    /// Injected sync failure for testing.
    #[cfg(test)]
    pub(crate) fail_sync: bool,
    /// Injected append failure for testing.
    #[cfg(test)]
    pub(crate) fail_append: bool,
}

impl WalWriter {
    /// Create a writer wrapping an already-open file at the given position.
    ///
    /// The file must already contain a valid WAL header at offset 0.
    pub fn new(file: File, write_pos: u64, config: WalWriterConfig) -> Self {
        Self {
            file,
            write_pos,
            config,
            appends_since_sync: 0,
            last_commit_seq: 0,
            next_operation_id: 1,
            #[cfg(test)]
            fail_sync: false,
            #[cfg(test)]
            fail_append: false,
        }
    }

    /// Create a fresh WAL file with header and return a writer positioned after it.
    pub fn create(path: &Path, config: WalWriterConfig) -> Result<Self> {
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(true)
            .open(path)?;

        let header = WalHeader::default();
        let header_bytes = wal::encode_header(&header);
        file.write_all(&header_bytes)?;
        file.sync_all()?;

        let write_pos = u64::try_from(HEADER_SIZE)
            .map_err(|_| FfsError::Format("header size overflow".to_owned()))?;

        Ok(Self::new(file, write_pos, config))
    }

    /// Append a commit record to the WAL.
    ///
    /// The record is encoded with CRC32C integrity, appended at the current
    /// write position, and optionally synced according to the configured
    /// [`SyncPolicy`].
    ///
    /// # Monotonicity (D1)
    ///
    /// The commit's `commit_seq` must be strictly greater than any previously
    /// appended commit (unless this is the first append).  Violations return
    /// [`WalWriteError::FormatViolation`].
    ///
    /// # Sentinel rejection (D8)
    ///
    /// `commit_seq == u64::MAX` or `txn_id == u64::MAX` are rejected.
    ///
    /// # Errors
    ///
    /// Returns a classified [`WalWriteError`] distinguishing retryable I/O
    /// failures from fatal format/invariant violations.
    pub fn append_commit(
        &mut self,
        commit: &WalCommit,
    ) -> std::result::Result<AppendResult, WalWriteError> {
        let op_id = self.next_op_id();
        let commit_seq = commit.commit_seq.0;
        let txn_id = commit.txn_id.0;
        let num_writes = commit.writes.len();

        debug!(
            operation_id = op_id,
            commit_seq,
            txn_id,
            num_writes,
            "wal_append_start"
        );

        // ── D8: reject reserved sentinels ────────────────────────────────
        if commit_seq == u64::MAX || txn_id == u64::MAX {
            error!(
                operation_id = op_id,
                commit_seq,
                txn_id,
                error_class = "format_violation",
                "wal_append_rejected_sentinel"
            );
            return Err(WalWriteError::FormatViolation {
                detail: "reserved sentinel value (u64::MAX) in commit_seq or txn_id".to_owned(),
            });
        }

        // ── D1: enforce strict monotonicity ──────────────────────────────
        if self.last_commit_seq > 0 && commit_seq <= self.last_commit_seq {
            error!(
                operation_id = op_id,
                commit_seq,
                last_commit_seq = self.last_commit_seq,
                error_class = "format_violation",
                "wal_append_rejected_monotonicity"
            );
            return Err(WalWriteError::FormatViolation {
                detail: format!(
                    "commit_seq {commit_seq} is not strictly greater than last appended {}",
                    self.last_commit_seq,
                ),
            });
        }

        // ── Backpressure check ───────────────────────────────────────────
        if self.config.backpressure_threshold_bytes > 0
            && self.write_pos >= self.config.backpressure_threshold_bytes
        {
            warn!(
                operation_id = op_id,
                wal_size = self.write_pos,
                threshold = self.config.backpressure_threshold_bytes,
                "wal_backpressure"
            );
            return Err(WalWriteError::Backpressure {
                wal_size: self.write_pos,
                threshold: self.config.backpressure_threshold_bytes,
            });
        }

        // ── Encode ───────────────────────────────────────────────────────
        let encoded = wal::encode_commit(commit).map_err(|e| WalWriteError::FormatViolation {
            detail: format!("failed to encode commit: {e}"),
        })?;
        let bytes_len = encoded.len();
        let write_offset = self.write_pos;

        // ── Append ───────────────────────────────────────────────────────
        #[cfg(test)]
        if self.fail_append {
            return Err(WalWriteError::AppendIo {
                source: std::io::Error::other("injected append failure"),
                bytes_attempted: bytes_len,
            });
        }

        self.raw_append(&encoded).map_err(|e| {
            error!(
                operation_id = op_id,
                commit_seq,
                bytes_attempted = bytes_len,
                error_class = "append_io",
                error = %e,
                "wal_append_err"
            );
            WalWriteError::AppendIo {
                source: e,
                bytes_attempted: bytes_len,
            }
        })?;

        // ── Optional write verification ──────────────────────────────────
        if self.config.verify_writes {
            self.verify_written_record(write_offset, &encoded, op_id)?;
        }

        // ── Sync policy ──────────────────────────────────────────────────
        self.appends_since_sync += 1;
        let synced = self.maybe_sync(op_id, commit_seq)?;

        self.last_commit_seq = commit_seq;

        let bytes_written = u64::try_from(bytes_len).unwrap_or(u64::MAX);

        info!(
            operation_id = op_id,
            commit_seq,
            txn_id,
            bytes_written,
            offset = write_offset,
            synced,
            "wal_append_ok"
        );

        Ok(AppendResult {
            offset: write_offset,
            bytes_written,
            synced,
            pending_sync_count: if synced {
                0
            } else {
                self.appends_since_sync
            },
        })
    }

    /// Force-sync all pending writes to disk.
    ///
    /// Returns the number of appends that were pending sync (0 if nothing was
    /// pending).
    pub fn flush(&mut self) -> std::result::Result<u32, WalWriteError> {
        let pending = self.appends_since_sync;
        if pending == 0 {
            return Ok(0);
        }
        let op_id = self.next_op_id();
        self.do_sync(op_id)?;
        info!(operation_id = op_id, flushed = pending, "wal_flush_ok");
        Ok(pending)
    }

    /// Current WAL file size (byte offset of the next write).
    #[must_use]
    pub fn size(&self) -> u64 {
        self.write_pos
    }

    /// Whether the WAL is currently above the backpressure threshold.
    #[must_use]
    pub fn is_backpressured(&self) -> bool {
        self.config.backpressure_threshold_bytes > 0
            && self.write_pos >= self.config.backpressure_threshold_bytes
    }

    /// Highest `commit_seq` successfully appended.
    #[must_use]
    pub fn last_commit_seq(&self) -> u64 {
        self.last_commit_seq
    }

    /// Number of appends pending sync.
    #[must_use]
    pub fn pending_sync_count(&self) -> u32 {
        self.appends_since_sync
    }

    /// Borrow the underlying file (for replay, truncation, etc.).
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Mutably borrow the underlying file.
    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    /// Set `last_commit_seq` (used after replay to synchronise writer state).
    pub fn set_last_commit_seq(&mut self, seq: u64) {
        self.last_commit_seq = seq;
    }

    /// Borrow the writer configuration.
    #[must_use]
    pub fn config(&self) -> &WalWriterConfig {
        &self.config
    }

    // ── Internal helpers ─────────────────────────────────────────────────

    fn next_op_id(&mut self) -> u64 {
        let id = self.next_operation_id;
        self.next_operation_id += 1;
        id
    }

    fn raw_append(&mut self, data: &[u8]) -> std::io::Result<()> {
        self.file.seek(SeekFrom::Start(self.write_pos))?;
        self.file.write_all(data)?;
        self.write_pos += u64::try_from(data.len()).unwrap_or(u64::MAX);
        Ok(())
    }

    fn verify_written_record(
        &mut self,
        offset: u64,
        expected: &[u8],
        op_id: u64,
    ) -> std::result::Result<(), WalWriteError> {
        let mut readback = vec![0_u8; expected.len()];
        self.file.seek(SeekFrom::Start(offset)).map_err(|e| {
            WalWriteError::AppendIo {
                source: e,
                bytes_attempted: expected.len(),
            }
        })?;
        self.file.read_exact(&mut readback).map_err(|e| {
            WalWriteError::AppendIo {
                source: e,
                bytes_attempted: expected.len(),
            }
        })?;

        let expected_crc = crc32c::crc32c(expected);
        let actual_crc = crc32c::crc32c(&readback);

        if expected_crc != actual_crc {
            error!(
                operation_id = op_id,
                offset,
                expected_crc,
                actual_crc,
                error_class = "verification_failed",
                "wal_verify_err"
            );
            return Err(WalWriteError::VerificationFailed {
                expected_crc,
                actual_crc,
                offset,
            });
        }

        debug!(
            operation_id = op_id,
            offset,
            crc = expected_crc,
            "wal_verify_ok"
        );

        Ok(())
    }

    fn maybe_sync(
        &mut self,
        op_id: u64,
        commit_seq: u64,
    ) -> std::result::Result<bool, WalWriteError> {
        let should_sync = match self.config.sync_policy {
            SyncPolicy::Immediate => true,
            SyncPolicy::EveryN(n) => self.appends_since_sync >= n,
            SyncPolicy::Manual => false,
        };

        if should_sync {
            self.do_sync(op_id)?;
            info!(operation_id = op_id, commit_seq, "wal_sync_ok");
            Ok(true)
        } else {
            Ok(false)
        }
    }

    fn do_sync(&mut self, op_id: u64) -> std::result::Result<(), WalWriteError> {
        #[cfg(test)]
        if self.fail_sync {
            return Err(WalWriteError::SyncIo {
                source: std::io::Error::other("injected sync failure"),
            });
        }

        self.file.sync_all().map_err(|e| {
            error!(
                operation_id = op_id,
                error_class = "sync_io",
                error = %e,
                "wal_sync_err"
            );
            WalWriteError::SyncIo { source: e }
        })?;

        self.appends_since_sync = 0;
        Ok(())
    }
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wal::{
        DecodeResult, WalWrite, {commit_byte_size, decode_commit, decode_header},
    };
    use ffs_types::{BlockNumber, CommitSeq, TxnId};
    use tempfile::NamedTempFile;

    fn make_commit(seq: u64, txn: u64, blocks: &[(u64, &[u8])]) -> WalCommit {
        WalCommit {
            commit_seq: CommitSeq(seq),
            txn_id: TxnId(txn),
            writes: blocks
                .iter()
                .map(|(b, d)| WalWrite {
                    block: BlockNumber(*b),
                    data: d.to_vec(),
                })
                .collect(),
        }
    }

    fn tmp_path() -> std::path::PathBuf {
        let t = NamedTempFile::new().expect("temp file");
        let p = t.path().to_path_buf();
        std::fs::remove_file(&p).ok();
        std::mem::forget(t); // prevent auto-delete
        p
    }

    // ── Basic append + decode ────────────────────────────────────────────

    #[test]
    fn append_single_commit_decodable() {
        let path = tmp_path();
        let mut w = WalWriter::create(&path, WalWriterConfig::default()).expect("create");

        let commit = make_commit(1, 1, &[(10, &[0xAA; 32])]);
        let result = w.append_commit(&commit).expect("append");
        assert!(result.synced);
        assert!(result.bytes_written > 0);
        assert_eq!(result.offset, HEADER_SIZE as u64);

        // Read back and decode
        let data = std::fs::read(&path).expect("read");
        decode_header(&data[..HEADER_SIZE]).expect("header");
        match decode_commit(&data[HEADER_SIZE..]) {
            DecodeResult::Commit(c) => {
                assert_eq!(c.commit_seq, CommitSeq(1));
                assert_eq!(c.txn_id, TxnId(1));
                assert_eq!(c.writes.len(), 1);
                assert_eq!(c.writes[0].block, BlockNumber(10));
                assert_eq!(c.writes[0].data, vec![0xAA; 32]);
            }
            other => panic!("expected Commit, got {other:?}"),
        }

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn append_multiple_commits_sequential_decode() {
        let path = tmp_path();
        let mut w = WalWriter::create(&path, WalWriterConfig::default()).expect("create");

        for i in 1_u64..=5 {
            let commit = make_commit(i, i, &[(i, &[i as u8; 16])]);
            w.append_commit(&commit).expect("append");
        }

        let data = std::fs::read(&path).expect("read");
        let mut offset = HEADER_SIZE;
        for i in 1_u64..=5 {
            match decode_commit(&data[offset..]) {
                DecodeResult::Commit(c) => {
                    assert_eq!(c.commit_seq, CommitSeq(i));
                    let size = commit_byte_size(&data[offset..]).expect("size");
                    offset += size;
                }
                other => panic!("expected Commit at seq {i}, got {other:?}"),
            }
        }

        let _ = std::fs::remove_file(&path);
    }

    // ── Monotonicity enforcement (D1) ────────────────────────────────────

    #[test]
    fn rejects_non_monotonic_commit_seq() {
        let path = tmp_path();
        let mut w = WalWriter::create(&path, WalWriterConfig::default()).expect("create");

        w.append_commit(&make_commit(5, 1, &[]))
            .expect("first append");

        // Same seq → rejected
        let err = w
            .append_commit(&make_commit(5, 2, &[]))
            .expect_err("duplicate seq");
        assert!(err.is_fatal());
        assert!(matches!(err, WalWriteError::FormatViolation { .. }));

        // Lower seq → rejected
        let err = w
            .append_commit(&make_commit(3, 3, &[]))
            .expect_err("lower seq");
        assert!(err.is_fatal());

        // Higher seq → accepted
        w.append_commit(&make_commit(6, 4, &[]))
            .expect("higher seq ok");

        let _ = std::fs::remove_file(&path);
    }

    // ── Sentinel rejection (D8) ──────────────────────────────────────────

    #[test]
    fn rejects_sentinel_commit_seq() {
        let path = tmp_path();
        let mut w = WalWriter::create(&path, WalWriterConfig::default()).expect("create");

        let err = w
            .append_commit(&make_commit(u64::MAX, 1, &[]))
            .expect_err("sentinel commit_seq");
        assert!(err.is_fatal());
        assert!(matches!(err, WalWriteError::FormatViolation { .. }));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn rejects_sentinel_txn_id() {
        let path = tmp_path();
        let mut w = WalWriter::create(&path, WalWriterConfig::default()).expect("create");

        let err = w
            .append_commit(&make_commit(1, u64::MAX, &[]))
            .expect_err("sentinel txn_id");
        assert!(err.is_fatal());

        let _ = std::fs::remove_file(&path);
    }

    // ── Backpressure ─────────────────────────────────────────────────────

    #[test]
    fn backpressure_threshold_triggers() {
        let path = tmp_path();
        let config = WalWriterConfig {
            backpressure_threshold_bytes: HEADER_SIZE as u64 + 50,
            ..WalWriterConfig::default()
        };
        let mut w = WalWriter::create(&path, config).expect("create");

        // First small commit should succeed
        w.append_commit(&make_commit(1, 1, &[(1, &[1; 8])]))
            .expect("under threshold");

        // Large commit that pushes us over
        w.append_commit(&make_commit(2, 2, &[(2, &[2; 64])]))
            .expect("at threshold append succeeds because checked before write");

        // Now WAL is above threshold → next append is rejected
        let err = w
            .append_commit(&make_commit(3, 3, &[(3, &[3; 8])]))
            .expect_err("backpressure");
        assert!(err.is_retryable());
        assert!(matches!(err, WalWriteError::Backpressure { .. }));
        assert!(w.is_backpressured());

        let _ = std::fs::remove_file(&path);
    }

    // ── Sync policy ──────────────────────────────────────────────────────

    #[test]
    fn sync_policy_immediate_syncs_every_write() {
        let path = tmp_path();
        let config = WalWriterConfig {
            sync_policy: SyncPolicy::Immediate,
            ..WalWriterConfig::default()
        };
        let mut w = WalWriter::create(&path, config).expect("create");

        for i in 1_u64..=3 {
            let r = w.append_commit(&make_commit(i, i, &[])).expect("append");
            assert!(r.synced, "commit {i} should be synced");
            assert_eq!(r.pending_sync_count, 0);
        }
        assert_eq!(w.pending_sync_count(), 0);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn sync_policy_every_n_batches_syncs() {
        let path = tmp_path();
        let config = WalWriterConfig {
            sync_policy: SyncPolicy::EveryN(3),
            ..WalWriterConfig::default()
        };
        let mut w = WalWriter::create(&path, config).expect("create");

        let r1 = w
            .append_commit(&make_commit(1, 1, &[]))
            .expect("append 1");
        assert!(!r1.synced);
        assert_eq!(r1.pending_sync_count, 1);

        let r2 = w
            .append_commit(&make_commit(2, 2, &[]))
            .expect("append 2");
        assert!(!r2.synced);
        assert_eq!(r2.pending_sync_count, 2);

        let r3 = w.append_commit(&make_commit(3, 3, &[])).expect("append 3");
        assert!(r3.synced, "third append should trigger sync");
        assert_eq!(r3.pending_sync_count, 0);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn sync_policy_manual_never_auto_syncs() {
        let path = tmp_path();
        let config = WalWriterConfig {
            sync_policy: SyncPolicy::Manual,
            ..WalWriterConfig::default()
        };
        let mut w = WalWriter::create(&path, config).expect("create");

        for i in 1_u64..=5 {
            let r = w.append_commit(&make_commit(i, i, &[])).expect("append");
            assert!(!r.synced);
        }
        assert_eq!(w.pending_sync_count(), 5);

        let flushed = w.flush().expect("flush");
        assert_eq!(flushed, 5);
        assert_eq!(w.pending_sync_count(), 0);

        let _ = std::fs::remove_file(&path);
    }

    // ── Write verification ───────────────────────────────────────────────

    #[test]
    fn verify_writes_reads_back_successfully() {
        let path = tmp_path();
        let config = WalWriterConfig {
            verify_writes: true,
            ..WalWriterConfig::default()
        };
        let mut w = WalWriter::create(&path, config).expect("create");

        let commit = make_commit(1, 1, &[(10, &[0xBB; 128])]);
        w.append_commit(&commit)
            .expect("verified append should succeed");

        let _ = std::fs::remove_file(&path);
    }

    // ── Fault injection ──────────────────────────────────────────────────

    #[test]
    fn append_failure_returns_retryable_error() {
        let path = tmp_path();
        let mut w = WalWriter::create(&path, WalWriterConfig::default()).expect("create");

        w.fail_append = true;
        let err = w
            .append_commit(&make_commit(1, 1, &[(1, &[1])]))
            .expect_err("injected failure");
        assert!(err.is_retryable());
        assert!(matches!(err, WalWriteError::AppendIo { .. }));

        // Writer state should be unchanged (no partial side effects)
        assert_eq!(w.last_commit_seq(), 0);
        assert_eq!(w.size(), HEADER_SIZE as u64);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn sync_failure_returns_classified_error() {
        let path = tmp_path();
        let mut w = WalWriter::create(&path, WalWriterConfig::default()).expect("create");

        w.fail_sync = true;
        let err = w
            .append_commit(&make_commit(1, 1, &[(1, &[1])]))
            .expect_err("injected sync failure");
        assert!(!err.is_retryable());
        assert!(!err.is_fatal());
        assert!(matches!(err, WalWriteError::SyncIo { .. }));

        let _ = std::fs::remove_file(&path);
    }

    // ── Error classification ─────────────────────────────────────────────

    #[test]
    fn error_classification_retryable() {
        let e = WalWriteError::AppendIo {
            source: std::io::Error::other("disk full"),
            bytes_attempted: 100,
        };
        assert!(e.is_retryable());
        assert!(!e.is_fatal());

        let e = WalWriteError::Backpressure {
            wal_size: 1000,
            threshold: 500,
        };
        assert!(e.is_retryable());
        assert!(!e.is_fatal());
    }

    #[test]
    fn error_classification_fatal() {
        let e = WalWriteError::FormatViolation {
            detail: "bad".to_owned(),
        };
        assert!(e.is_fatal());
        assert!(!e.is_retryable());

        let e = WalWriteError::VerificationFailed {
            expected_crc: 1,
            actual_crc: 2,
            offset: 0,
        };
        assert!(e.is_fatal());
        assert!(!e.is_retryable());
    }

    #[test]
    fn error_classification_sync_io_neither() {
        let e = WalWriteError::SyncIo {
            source: std::io::Error::other("oops"),
        };
        assert!(!e.is_retryable());
        assert!(!e.is_fatal());
    }

    // ── Conversion to FfsError ───────────────────────────────────────────

    #[test]
    fn wal_write_error_converts_to_ffs_error() {
        let e: FfsError = WalWriteError::AppendIo {
            source: std::io::Error::other("boom"),
            bytes_attempted: 10,
        }
        .into();
        assert!(matches!(e, FfsError::Io(_)));

        let e: FfsError = WalWriteError::FormatViolation {
            detail: "bad".to_owned(),
        }
        .into();
        assert!(matches!(e, FfsError::Format(_)));

        let e: FfsError = WalWriteError::VerificationFailed {
            expected_crc: 1,
            actual_crc: 2,
            offset: 0,
        }
        .into();
        assert!(matches!(e, FfsError::Corruption { .. }));
    }

    // ── Property: monotonic ordering across random sequences ─────────────

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(32))]

        #[test]
        fn proptest_monotonic_ordering_preserved(
            seq_increments in proptest::collection::vec(1_u64..100, 1..20),
        ) {
            let path = tmp_path();
            let mut w = WalWriter::create(&path, WalWriterConfig {
                sync_policy: SyncPolicy::Manual,
                ..WalWriterConfig::default()
            }).expect("create");

            let mut current_seq = 0_u64;
            for delta in &seq_increments {
                current_seq += delta;
                let commit = make_commit(current_seq, current_seq, &[]);
                w.append_commit(&commit).expect("monotonic append");
            }

            // Read back and verify ordering
            let data = std::fs::read(&path).expect("read");
            let mut offset = HEADER_SIZE;
            let mut last_seq = 0_u64;
            while offset < data.len() {
                match decode_commit(&data[offset..]) {
                    DecodeResult::Commit(c) => {
                        prop_assert!(
                            c.commit_seq.0 > last_seq,
                            "decoded seq {} not > previous {}",
                            c.commit_seq.0,
                            last_seq
                        );
                        last_seq = c.commit_seq.0;
                        let size = commit_byte_size(&data[offset..]).expect("size");
                        offset += size;
                    }
                    DecodeResult::EndOfData => break,
                    other => {
                        prop_assert!(false, "unexpected decode result: {:?}", other);
                    }
                }
            }

            let _ = std::fs::remove_file(&path);
        }
    }

    // ── Flush when nothing pending ───────────────────────────────────────

    #[test]
    fn flush_with_nothing_pending_returns_zero() {
        let path = tmp_path();
        let mut w = WalWriter::create(&path, WalWriterConfig::default()).expect("create");

        let flushed = w.flush().expect("flush");
        assert_eq!(flushed, 0);

        let _ = std::fs::remove_file(&path);
    }

    // ── last_commit_seq tracking ─────────────────────────────────────────

    #[test]
    fn last_commit_seq_tracks_appended_commits() {
        let path = tmp_path();
        let mut w = WalWriter::create(&path, WalWriterConfig::default()).expect("create");

        assert_eq!(w.last_commit_seq(), 0);

        w.append_commit(&make_commit(10, 1, &[])).expect("append");
        assert_eq!(w.last_commit_seq(), 10);

        w.append_commit(&make_commit(20, 2, &[])).expect("append");
        assert_eq!(w.last_commit_seq(), 20);

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn set_last_commit_seq_for_replay_sync() {
        let path = tmp_path();
        let mut w = WalWriter::create(&path, WalWriterConfig::default()).expect("create");

        w.set_last_commit_seq(100);
        assert_eq!(w.last_commit_seq(), 100);

        // Now appending seq 50 should fail (non-monotonic)
        let err = w
            .append_commit(&make_commit(50, 1, &[]))
            .expect_err("non-monotonic after set");
        assert!(err.is_fatal());

        // But seq 101 should succeed
        w.append_commit(&make_commit(101, 2, &[]))
            .expect("monotonic after set");

        let _ = std::fs::remove_file(&path);
    }
}
