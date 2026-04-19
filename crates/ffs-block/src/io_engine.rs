//! Pluggable I/O engine abstraction for kernel-bypass backends.
//!
//! Defines the [`IoEngine`] trait that abstracts over different I/O
//! submission strategies:
//!
//! - **[`PreadPwriteEngine`]**: Standard `pread`/`pwrite` syscalls (default).
//! - **io_uring** (future, behind `iouring` feature flag): Linux 5.1+
//!   submission queue for async I/O without syscall overhead per operation.
//! - **SPDK** (future): User-space NVMe driver for zero-copy DMA.
//!
//! # Design
//!
//! The engine handles batch I/O submission. Callers build a batch of
//! [`IoOp`] requests (read/write/sync), submit them to the engine, and
//! receive [`IoCompletion`] results. This maps naturally to io_uring's
//! submission/completion queue model while also working for synchronous
//! engines that execute operations immediately.
//!
//! # Integration with [`super::VectoredBlockDevice`]
//!
//! The `VectoredBlockDevice` trait can delegate to an `IoEngine` for
//! true vectored I/O when available, falling back to scalar operations
//! on engines that don't support batching.
//!
//! # `unsafe_code = "forbid"` Compliance
//!
//! All engines use safe Rust. The io_uring engine (when implemented)
//! will use a safe wrapper crate (`io-uring` or similar) that handles
//! the unsafe kernel interface internally.

use ffs_error::{FfsError, Result};
use std::path::Path;
use std::sync::Arc;

/// A single I/O operation in a batch.
#[derive(Debug)]
pub enum IoOp {
    /// Read `len` bytes from `offset` into the provided buffer.
    Read {
        /// File offset in bytes.
        offset: u64,
        /// Buffer to read into.
        buf: Vec<u8>,
    },
    /// Write `data` at `offset`.
    Write {
        /// File offset in bytes.
        offset: u64,
        /// Data to write.
        data: Vec<u8>,
    },
    /// Sync (fdatasync).
    Sync,
}

/// Result of a completed I/O operation.
#[derive(Debug)]
pub enum IoCompletion {
    /// Read completed: returns the filled buffer.
    Read(Vec<u8>),
    /// Write completed.
    Write,
    /// Sync completed.
    Sync,
    /// Operation failed.
    Error(FfsError),
}

/// I/O engine statistics.
#[derive(Debug, Clone, Default)]
pub struct IoEngineStats {
    /// Total reads submitted.
    pub reads: u64,
    /// Total writes submitted.
    pub writes: u64,
    /// Total syncs submitted.
    pub syncs: u64,
    /// Total bytes read.
    pub bytes_read: u64,
    /// Total bytes written.
    pub bytes_written: u64,
    /// Total batches submitted.
    pub batches: u64,
}

/// Pluggable I/O engine interface.
///
/// Engines accept a batch of I/O operations and return completions.
/// This models both synchronous (pread/pwrite) and asynchronous
/// (io_uring, SPDK) backends.
pub trait IoEngine: Send + Sync {
    /// Submit a batch of I/O operations and return their completions.
    ///
    /// Completions are returned in the same order as the input operations.
    /// For synchronous engines, this blocks until all operations complete.
    /// For async engines, this submits to the queue and polls for completion.
    fn submit_batch(&self, ops: Vec<IoOp>) -> Vec<IoCompletion>;

    /// Engine name for diagnostics.
    fn name(&self) -> &'static str;

    /// Current statistics.
    fn stats(&self) -> IoEngineStats;
}

// ── pread/pwrite engine ────────────────────────────────────────────────────

/// Standard `pread`/`pwrite` I/O engine.
///
/// Each operation maps to a single syscall. Simple and portable,
/// but incurs syscall overhead per I/O and cannot overlap operations.
pub struct PreadPwriteEngine {
    file: Arc<std::fs::File>,
    stats: parking_lot::Mutex<IoEngineStats>,
}

impl PreadPwriteEngine {
    /// Open a file for I/O with this engine.
    ///
    /// Opens read-write if possible, read-only otherwise.
    pub fn open(path: &Path) -> Result<Self> {
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .or_else(|_| std::fs::OpenOptions::new().read(true).open(path))
            .map_err(FfsError::Io)?;

        Ok(Self {
            file: Arc::new(file),
            stats: parking_lot::Mutex::new(IoEngineStats::default()),
        })
    }

    /// Create from an existing open file.
    #[must_use]
    pub fn from_file(file: Arc<std::fs::File>) -> Self {
        Self {
            file,
            stats: parking_lot::Mutex::new(IoEngineStats::default()),
        }
    }
}

impl std::fmt::Debug for PreadPwriteEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PreadPwriteEngine")
            .field("stats", &*self.stats.lock())
            .finish_non_exhaustive()
    }
}

impl IoEngine for PreadPwriteEngine {
    fn submit_batch(&self, ops: Vec<IoOp>) -> Vec<IoCompletion> {
        use std::os::unix::fs::FileExt;

        {
            let mut stats = self.stats.lock();
            stats.batches += 1;
        }

        let results: Vec<IoCompletion> = ops
            .into_iter()
            .map(|op| match op {
                IoOp::Read { offset, mut buf } => {
                    self.stats.lock().reads += 1;
                    match self.file.read_exact_at(&mut buf, offset) {
                        Ok(()) => {
                            let n = buf.len() as u64;
                            let mut s = self.stats.lock();
                            s.bytes_read += n;
                            drop(s);
                            IoCompletion::Read(buf)
                        }
                        Err(e) => IoCompletion::Error(FfsError::Io(e)),
                    }
                }
                IoOp::Write { offset, data } => {
                    self.stats.lock().writes += 1;
                    match self.file.write_all_at(&data, offset) {
                        Ok(()) => {
                            let mut s = self.stats.lock();
                            s.bytes_written += data.len() as u64;
                            drop(s);
                            IoCompletion::Write
                        }
                        Err(e) => IoCompletion::Error(FfsError::Io(e)),
                    }
                }
                IoOp::Sync => {
                    self.stats.lock().syncs += 1;
                    match self.file.sync_all() {
                        Ok(()) => IoCompletion::Sync,
                        Err(e) => IoCompletion::Error(FfsError::Io(e)),
                    }
                }
            })
            .collect();
        results
    }

    fn name(&self) -> &'static str {
        "pread/pwrite"
    }

    fn stats(&self) -> IoEngineStats {
        self.stats.lock().clone()
    }
}

// ── In-memory engine (for testing) ─────────────────────────────────────────

/// In-memory I/O engine for testing and benchmarking.
///
/// All I/O operates on a `Vec<u8>` buffer, eliminating disk latency
/// to isolate engine overhead.
pub struct MemIoEngine {
    data: parking_lot::Mutex<Vec<u8>>,
    stats: parking_lot::Mutex<IoEngineStats>,
}

impl MemIoEngine {
    /// Create a new in-memory engine with the given size in bytes.
    #[must_use]
    pub fn new(size: usize) -> Self {
        Self {
            data: parking_lot::Mutex::new(vec![0_u8; size]),
            stats: parking_lot::Mutex::new(IoEngineStats::default()),
        }
    }
}

impl std::fmt::Debug for MemIoEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MemIoEngine")
            .field("size", &self.data.lock().len())
            .finish_non_exhaustive()
    }
}

impl IoEngine for MemIoEngine {
    #[expect(clippy::cast_possible_truncation)] // 64-bit offsets in memory engine
    fn submit_batch(&self, ops: Vec<IoOp>) -> Vec<IoCompletion> {
        let mut data = self.data.lock();
        self.stats.lock().batches += 1;

        let results: Vec<IoCompletion> = ops
            .into_iter()
            .map(|op| match op {
                IoOp::Read { offset, mut buf } => {
                    self.stats.lock().reads += 1;
                    let start = offset as usize;
                    let end = start + buf.len();
                    if end > data.len() {
                        return IoCompletion::Error(FfsError::Io(std::io::Error::new(
                            std::io::ErrorKind::UnexpectedEof,
                            "read past end of memory",
                        )));
                    }
                    buf.copy_from_slice(&data[start..end]);
                    let n = buf.len() as u64;
                    let mut s = self.stats.lock();
                    s.bytes_read += n;
                    drop(s);
                    IoCompletion::Read(buf)
                }
                IoOp::Write { offset, data: wd } => {
                    self.stats.lock().writes += 1;
                    let start = offset as usize;
                    let end = start + wd.len();
                    if end > data.len() {
                        return IoCompletion::Error(FfsError::Io(std::io::Error::new(
                            std::io::ErrorKind::WriteZero,
                            "write past end of memory",
                        )));
                    }
                    data[start..end].copy_from_slice(&wd);
                    let mut s = self.stats.lock();
                    s.bytes_written += wd.len() as u64;
                    IoCompletion::Write
                }
                IoOp::Sync => {
                    self.stats.lock().syncs += 1;
                    IoCompletion::Sync
                }
            })
            .collect();
        results
    }

    fn name(&self) -> &'static str {
        "memory"
    }

    fn stats(&self) -> IoEngineStats {
        self.stats.lock().clone()
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[derive(Clone, Debug)]
    enum MemOpPlan {
        Read { offset: usize, len: usize },
        Write { offset: usize, data: Vec<u8> },
        Sync,
    }

    fn mem_op_plan_strategy(max_size: usize) -> impl Strategy<Value = MemOpPlan> {
        let read_op = (0_usize..max_size)
            .prop_flat_map(move |offset| {
                let max_len = (max_size - offset).min(64);
                (Just(offset), 1_usize..=max_len)
            })
            .prop_map(|(offset, len)| MemOpPlan::Read { offset, len });

        let write_op = (0_usize..max_size)
            .prop_flat_map(move |offset| {
                let max_len = (max_size - offset).min(64);
                (
                    Just(offset),
                    prop::collection::vec(any::<u8>(), 1_usize..=max_len),
                )
            })
            .prop_map(|(offset, data)| MemOpPlan::Write { offset, data });

        prop_oneof![3 => read_op, 3 => write_op, 1 => Just(MemOpPlan::Sync)]
    }

    #[test]
    fn mem_engine_read_write_roundtrip() {
        let engine = MemIoEngine::new(4096);

        // Write 4K of data.
        let data = vec![0xAB_u8; 4096];
        let completions = engine.submit_batch(vec![IoOp::Write {
            offset: 0,
            data: data.clone(),
        }]);
        assert!(matches!(completions[0], IoCompletion::Write));

        // Read it back.
        let completions = engine.submit_batch(vec![IoOp::Read {
            offset: 0,
            buf: vec![0_u8; 4096],
        }]);
        assert!(matches!(completions[0], IoCompletion::Read(_)));
        if let IoCompletion::Read(buf) = &completions[0] {
            assert_eq!(buf, &data);
        }
    }

    #[test]
    fn mem_engine_batch_operations() {
        let engine = MemIoEngine::new(8192);

        // Submit a batch: write + write + read.
        let completions = engine.submit_batch(vec![
            IoOp::Write {
                offset: 0,
                data: vec![1_u8; 4096],
            },
            IoOp::Write {
                offset: 4096,
                data: vec![2_u8; 4096],
            },
            IoOp::Read {
                offset: 0,
                buf: vec![0_u8; 4096],
            },
        ]);

        assert!(matches!(completions[0], IoCompletion::Write));
        assert!(matches!(completions[1], IoCompletion::Write));
        assert!(
            matches!(completions[2], IoCompletion::Read(_)),
            "expected Read, got {:?}",
            completions[2]
        );
        if let IoCompletion::Read(buf) = &completions[2] {
            assert_eq!(buf[0], 1);
        }
    }

    #[test]
    fn mem_engine_read_past_end_returns_error() {
        let engine = MemIoEngine::new(1024);

        let completions = engine.submit_batch(vec![IoOp::Read {
            offset: 512,
            buf: vec![0_u8; 1024], // 512 + 1024 > 1024
        }]);

        assert!(matches!(completions[0], IoCompletion::Error(_)));
        let stats = engine.stats();
        assert_eq!(stats.batches, 1);
        assert_eq!(stats.reads, 1);
        assert_eq!(stats.bytes_read, 0);
    }

    #[test]
    fn mem_engine_sync_succeeds() {
        let engine = MemIoEngine::new(1024);
        let completions = engine.submit_batch(vec![IoOp::Sync]);
        assert!(matches!(completions[0], IoCompletion::Sync));
    }

    #[test]
    fn mem_engine_stats_tracking() {
        let engine = MemIoEngine::new(4096);

        engine.submit_batch(vec![
            IoOp::Write {
                offset: 0,
                data: vec![0_u8; 1024],
            },
            IoOp::Read {
                offset: 0,
                buf: vec![0_u8; 512],
            },
            IoOp::Sync,
        ]);

        let stats = engine.stats();
        assert_eq!(stats.reads, 1);
        assert_eq!(stats.writes, 1);
        assert_eq!(stats.syncs, 1);
        assert_eq!(stats.bytes_written, 1024);
        assert_eq!(stats.bytes_read, 512);
        assert_eq!(stats.batches, 1);
    }

    #[test]
    fn mem_engine_multiple_batches_accumulate() {
        let engine = MemIoEngine::new(4096);

        engine.submit_batch(vec![IoOp::Write {
            offset: 0,
            data: vec![0_u8; 100],
        }]);
        engine.submit_batch(vec![IoOp::Write {
            offset: 100,
            data: vec![0_u8; 200],
        }]);

        let stats = engine.stats();
        assert_eq!(stats.writes, 2);
        assert_eq!(stats.bytes_written, 300);
        assert_eq!(stats.batches, 2);
    }

    #[test]
    fn pread_pwrite_engine_from_tempfile() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.img");

        // Create a 4K file.
        std::fs::write(&path, vec![0_u8; 4096]).unwrap();

        let engine = PreadPwriteEngine::open(&path).unwrap();
        assert_eq!(engine.name(), "pread/pwrite");

        // Write + read roundtrip.
        let data = vec![0x42_u8; 512];
        let completions = engine.submit_batch(vec![IoOp::Write {
            offset: 0,
            data: data.clone(),
        }]);
        assert!(matches!(completions[0], IoCompletion::Write));

        let completions = engine.submit_batch(vec![IoOp::Read {
            offset: 0,
            buf: vec![0_u8; 512],
        }]);
        assert!(matches!(completions[0], IoCompletion::Read(_)));
        if let IoCompletion::Read(buf) = &completions[0] {
            assert_eq!(buf, &data);
        }

        // Check stats.
        let stats = engine.stats();
        assert_eq!(stats.reads, 1);
        assert_eq!(stats.writes, 1);
    }

    #[test]
    fn pread_pwrite_engine_failed_read_counts_submission_but_not_bytes() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("short.img");
        std::fs::write(&path, vec![0_u8; 16]).unwrap();

        let engine = PreadPwriteEngine::open(&path).unwrap();
        let completions = engine.submit_batch(vec![IoOp::Read {
            offset: 8,
            buf: vec![0_u8; 32],
        }]);

        assert!(matches!(completions[0], IoCompletion::Error(_)));
        let stats = engine.stats();
        assert_eq!(stats.batches, 1);
        assert_eq!(stats.reads, 1);
        assert_eq!(stats.bytes_read, 0);
    }

    #[test]
    fn batch_vs_scalar_same_result() {
        let engine = MemIoEngine::new(8192);

        // Write blocks individually.
        for i in 0..4 {
            let byte = u8::try_from(i + 1).expect("test byte fits in u8");
            engine.submit_batch(vec![IoOp::Write {
                offset: i * 2048,
                data: vec![byte; 2048],
            }]);
        }

        // Read them back as a batch.
        let completions = engine.submit_batch(vec![
            IoOp::Read {
                offset: 0,
                buf: vec![0_u8; 2048],
            },
            IoOp::Read {
                offset: 2048,
                buf: vec![0_u8; 2048],
            },
            IoOp::Read {
                offset: 4096,
                buf: vec![0_u8; 2048],
            },
            IoOp::Read {
                offset: 6144,
                buf: vec![0_u8; 2048],
            },
        ]);

        for (i, comp) in completions.iter().enumerate() {
            let expected = u8::try_from(i + 1).expect("test byte fits in u8");
            match comp {
                IoCompletion::Read(buf) => {
                    assert_eq!(buf[0], expected, "block {i} mismatch");
                }
                other => panic!("expected Read, got {other:?}"),
            }
        }
    }

    #[test]
    fn engine_name_correct() {
        let mem = MemIoEngine::new(1024);
        assert_eq!(mem.name(), "memory");
    }

    #[test]
    fn representative_io_engine_debug_exact_golden_contract() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("engine.img");
        std::fs::write(&path, vec![0_u8; 64]).expect("seed file");

        let pread = PreadPwriteEngine::open(&path).expect("open");
        let mem = MemIoEngine::new(128);
        let actual = [
            format!(
                "{:?}",
                IoOp::Read {
                    offset: 7,
                    buf: vec![1, 2, 3],
                }
            ),
            format!("{:?}", IoCompletion::Read(vec![4, 5])),
            format!(
                "{:?}",
                IoEngineStats {
                    reads: 1,
                    writes: 2,
                    syncs: 3,
                    bytes_read: 4,
                    bytes_written: 5,
                    batches: 6,
                }
            ),
            format!("{mem:?}"),
            format!("{pread:?}"),
        ]
        .join("\n");

        let expected = concat!(
            "Read { offset: 7, buf: [1, 2, 3] }\n",
            "Read([4, 5])\n",
            "IoEngineStats { reads: 1, writes: 2, syncs: 3, bytes_read: 4, bytes_written: 5, batches: 6 }\n",
            "MemIoEngine { size: 128, .. }\n",
            "PreadPwriteEngine { stats: IoEngineStats { reads: 0, writes: 0, syncs: 0, bytes_read: 0, bytes_written: 0, batches: 0 }, .. }"
        );
        assert_eq!(actual, expected);
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(96))]

        #[test]
        fn mem_engine_proptest_batch_semantics_and_stats(
            script in prop::collection::vec(mem_op_plan_strategy(512), 1..80),
        ) {
            const MEM_SIZE: usize = 512;

            let engine = MemIoEngine::new(MEM_SIZE);
            let mut model = vec![0_u8; MEM_SIZE];

            let ops: Vec<IoOp> = script
                .iter()
                .map(|plan| match plan {
                    MemOpPlan::Read { offset, len } => IoOp::Read {
                        offset: u64::try_from(*offset).expect("offset fits in u64"),
                        buf: vec![0_u8; *len],
                    },
                    MemOpPlan::Write { offset, data } => IoOp::Write {
                        offset: u64::try_from(*offset).expect("offset fits in u64"),
                        data: data.clone(),
                    },
                    MemOpPlan::Sync => IoOp::Sync,
                })
                .collect();

            let completions = engine.submit_batch(ops);
            prop_assert_eq!(completions.len(), script.len());

            let mut expected_reads = 0_u64;
            let mut expected_writes = 0_u64;
            let mut expected_syncs = 0_u64;
            let mut expected_bytes_read = 0_u64;
            let mut expected_bytes_written = 0_u64;

            for (plan, completion) in script.iter().zip(completions.iter()) {
                match plan {
                    MemOpPlan::Read { offset, len } => {
                        expected_reads += 1;
                        expected_bytes_read +=
                            u64::try_from(*len).expect("read length fits in u64");
                        match completion {
                            IoCompletion::Read(buf) => {
                                prop_assert_eq!(buf.len(), *len);
                                prop_assert_eq!(buf.as_slice(), &model[*offset..(*offset + *len)]);
                            }
                            other => prop_assert!(false, "expected Read completion, got {other:?}"),
                        }
                    }
                    MemOpPlan::Write { offset, data } => {
                        expected_writes += 1;
                        expected_bytes_written +=
                            u64::try_from(data.len()).expect("write length fits in u64");
                        match completion {
                            IoCompletion::Write => {
                                model[*offset..(*offset + data.len())].copy_from_slice(data);
                            }
                            other => prop_assert!(false, "expected Write completion, got {other:?}"),
                        }
                    }
                    MemOpPlan::Sync => {
                        expected_syncs += 1;
                        prop_assert!(matches!(completion, IoCompletion::Sync));
                    }
                }
            }

            let stats = engine.stats();
            prop_assert_eq!(stats.batches, 1);
            prop_assert_eq!(stats.reads, expected_reads);
            prop_assert_eq!(stats.writes, expected_writes);
            prop_assert_eq!(stats.syncs, expected_syncs);
            prop_assert_eq!(stats.bytes_read, expected_bytes_read);
            prop_assert_eq!(stats.bytes_written, expected_bytes_written);
        }

        #[test]
        fn mem_engine_proptest_read_oob_is_error_and_not_counted(
            size in 1_usize..1024,
            offset in 0_usize..2048,
            len in 1_usize..1024,
        ) {
            prop_assume!(offset > size || len > (size - offset));

            let engine = MemIoEngine::new(size);
            let completions = engine.submit_batch(vec![IoOp::Read {
                offset: u64::try_from(offset).expect("offset fits in u64"),
                buf: vec![0_u8; len],
            }]);

            prop_assert_eq!(completions.len(), 1);
            prop_assert!(matches!(completions[0], IoCompletion::Error(_)));

            let stats = engine.stats();
            prop_assert_eq!(stats.batches, 1);
            prop_assert_eq!(stats.reads, 1);
            prop_assert_eq!(stats.bytes_read, 0);
        }

        #[test]
        fn mem_engine_proptest_write_oob_is_error_and_not_counted(
            size in 1_usize..1024,
            offset in 0_usize..2048,
            len in 1_usize..1024,
            payload in prop::collection::vec(any::<u8>(), 1_usize..1024),
        ) {
            let write_len = len.min(payload.len());
            prop_assume!(offset > size || write_len > (size - offset));

            let engine = MemIoEngine::new(size);
            let completions = engine.submit_batch(vec![IoOp::Write {
                offset: u64::try_from(offset).expect("offset fits in u64"),
                data: payload[..write_len].to_vec(),
            }]);

            prop_assert_eq!(completions.len(), 1);
            prop_assert!(matches!(completions[0], IoCompletion::Error(_)));

            let stats = engine.stats();
            prop_assert_eq!(stats.batches, 1);
            prop_assert_eq!(stats.writes, 1);
            prop_assert_eq!(stats.bytes_written, 0);
        }
    }
}
