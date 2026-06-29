//! MVCC store abstraction for the OpenFs hot path.
//!
//! `OpenFs` needs one uniform `&self` API over two lock models:
//! the legacy single `RwLock<MvccStore>` path and the sharded parallel-write
//! path. Keeping this adapter in `ffs-core` avoids changing the public
//! `ffs-mvcc::MvccBlockDevice` API while the filesystem wiring moves over.

use asupersync::Cx;
use ffs_block::{BlockBuf, BlockDevice};
use ffs_error::{FfsError, Result as FfsResult};
use ffs_mvcc::sharded::ShardedMvccStore;
use ffs_mvcc::{
    BlockVersionStats, CommitError, EbrVersionStats, MvccStore, Transaction,
    TransactionOutcomeStats, TxnAbortReason,
};
use ffs_types::{BlockNumber, CommitSeq, Snapshot};
use parking_lot::RwLock;
use std::sync::Arc;

const MVCC_COMMIT_PRUNE_INTERVAL: u64 = 256;

// ── Intra-op write batching (bd-bhh0i) ──────────────────────────────────────
//
// The no-tx writable adapter (`FsMvccBlockDevice::write_block`) commits per
// single block, so one metadata FsOp (a create touches inode-table, bitmaps,
// dir block, …) becomes N independent commits — each through the global
// in-order `CommitPublicationGate` + a `next_commit`/prune cycle. Under an op
// batch, all of an op's block writes STAGE into one thread-local buffer and
// commit ONCE at op end (1 commit / FsOp), the §15.4 metadata analog of the
// FUSE data writeback-batch. Reads within the op consult the staged buffer
// first (read-your-writes), so correctness is preserved and a failed op simply
// discards the buffer (atomic rollback — strictly safer than per-block commit).
//
// Env-gated `FFS_OP_BATCH=0` reverts to per-block commit for A/B.

use std::cell::RefCell;
use std::collections::BTreeMap;

struct OpBatch {
    writes: BTreeMap<BlockNumber, Vec<u8>>,
    depth: u32,
}

thread_local! {
    static OP_BATCH: RefCell<Option<OpBatch>> = const { RefCell::new(None) };
}

fn op_batch_feature_enabled() -> bool {
    use std::sync::OnceLock;
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("FFS_OP_BATCH")
            .map(|v| v != "0")
            .unwrap_or(true)
    })
}

/// Begin (or re-enter) an op batch on this thread. No-op when the feature is
/// disabled. Nested begins increment a depth so only the outermost end commits.
pub(super) fn op_batch_begin() {
    if !op_batch_feature_enabled() {
        return;
    }
    OP_BATCH.with(|b| {
        let mut slot = b.borrow_mut();
        match slot.as_mut() {
            Some(batch) => batch.depth = batch.depth.saturating_add(1),
            None => {
                *slot = Some(OpBatch {
                    writes: BTreeMap::new(),
                    depth: 1,
                });
            }
        }
    });
}

/// True if writes on this thread should stage into the op batch.
pub(super) fn op_batch_active() -> bool {
    OP_BATCH.with(|b| b.borrow().is_some())
}

fn op_batch_stage(block: BlockNumber, data: Vec<u8>) {
    OP_BATCH.with(|b| {
        if let Some(batch) = b.borrow_mut().as_mut() {
            batch.writes.insert(block, data);
        }
    });
}

fn op_batch_get(block: BlockNumber) -> Option<Vec<u8>> {
    OP_BATCH.with(|b| {
        b.borrow()
            .as_ref()
            .and_then(|batch| batch.writes.get(&block).cloned())
    })
}

/// End the outermost batch and return its staged writes for a single commit;
/// returns `None` for a nested end (decrements depth) or when inactive. Use
/// [`op_batch_abort`] on the error path to discard instead.
fn op_batch_end_take() -> Option<BTreeMap<BlockNumber, Vec<u8>>> {
    OP_BATCH.with(|b| {
        let mut slot = b.borrow_mut();
        if let Some(batch) = slot.as_mut() {
            if batch.depth > 1 {
                batch.depth -= 1;
                return None;
            }
        }
        slot.take().map(|batch| batch.writes)
    })
}

/// Discard the outermost batch without committing (error/rollback path).
pub(super) fn op_batch_abort() {
    OP_BATCH.with(|b| {
        let mut slot = b.borrow_mut();
        if let Some(batch) = slot.as_mut() {
            if batch.depth > 1 {
                batch.depth -= 1;
                return;
            }
        }
        *slot = None;
    });
}

/// The OpenFs MVCC store: single-lock or sharded, behind a uniform `&self` API.
///
/// The enum is always owned behind `Arc`; boxing a variant would add another
/// hot-path indirection without reducing the outer handle size.
#[allow(clippy::large_enum_variant)]
pub enum FsMvccStore {
    /// Single store behind a `RwLock`: legacy, JBD2, and MVCC-WAL configured path.
    Single(RwLock<MvccStore>),
    /// Sharded store: default in-memory parallel-write path.
    Sharded(ShardedMvccStore),
}

impl FsMvccStore {
    pub(super) fn single() -> Self {
        Self::Single(RwLock::new(MvccStore::new()))
    }

    pub(super) fn sharded() -> Self {
        // Size shards to the host (available_parallelism, bounded) rather than a
        // fixed 8: at 16/32 disjoint parallel writers the 8-shard cap adds
        // shard-lock contention that host-sized sharding avoids (measured
        // sharded_mvcc_disjoint: 16w 3.74->3.21 ms = 1.17x, 32w 10.53->8.15 ms
        // = 1.29x; 8w neutral). Correctness-identical (more shards, same
        // semantics) and the documented preferred high-core constructor. The
        // residual parallel-write gap (bd-bhh0i) is the global active_snapshots
        // lock, not shard count (docs/NEGATIVE_EVIDENCE.md).
        Self::Sharded(ShardedMvccStore::for_host_parallelism())
    }

    pub(super) const fn is_sharded(&self) -> bool {
        matches!(self, Self::Sharded(_))
    }

    pub(super) fn begin(&self) -> Transaction {
        match self {
            Self::Single(lock) => lock.write().begin(),
            Self::Sharded(store) => store.begin(),
        }
    }

    /// Commit this thread's outermost op batch (if any) as ONE transaction
    /// (bd-bhh0i). Returns the commit seq if a non-empty batch committed,
    /// `None` for a nested end / inactive / empty batch. On commit error the
    /// staged writes are dropped (the op had already failed-safe).
    pub(super) fn op_batch_commit_if_active(&self) -> Result<Option<CommitSeq>, CommitError> {
        let Some(writes) = op_batch_end_take() else {
            return Ok(None);
        };
        if writes.is_empty() {
            return Ok(None);
        }
        if std::env::var("FFS_OP_BATCH_DEBUG").is_ok() {
            let blocks: Vec<u64> = writes.keys().map(|b| b.0).collect();
            let gd = writes.get(&BlockNumber(1)).map(|buf| {
                let fb = |g: usize| -> u16 {
                    let o = g * 64 + 0x0c;
                    if o + 2 <= buf.len() {
                        u16::from_le_bytes([buf[o], buf[o + 1]])
                    } else {
                        0
                    }
                };
                (fb(0), fb(1), fb(2), fb(3))
            });
            eprintln!(
                "OPBATCH_COMMIT n={} blocks={blocks:?} gdt_fb(g0,g1,g2,g3)={gd:?}",
                blocks.len()
            );
        }
        let mut txn = self.begin();
        for (block, data) in writes {
            txn.stage_write(block, data);
        }
        let commit_seq = self.commit(txn)?;
        self.prune_after_commit_if_due(commit_seq);
        Ok(Some(commit_seq))
    }

    pub(super) fn commit(&self, txn: Transaction) -> Result<CommitSeq, CommitError> {
        match self {
            Self::Single(lock) => lock.write().commit(txn),
            Self::Sharded(store) => store.commit(txn).map_err(|(error, _txn)| error),
        }
    }

    pub(super) fn commit_ssi(&self, txn: Transaction) -> Result<CommitSeq, CommitError> {
        match self {
            Self::Single(lock) => lock.write().commit_ssi(txn),
            Self::Sharded(store) => store.commit_ssi(txn).map_err(|(error, _txn)| error),
        }
    }

    pub(super) fn abort(&self, txn: Transaction, reason: TxnAbortReason, detail: Option<String>) {
        match self {
            Self::Single(lock) => lock.write().abort(txn, reason, detail),
            Self::Sharded(_) => drop((txn, reason, detail)),
        }
    }

    pub(super) fn read_visible(&self, block: BlockNumber, snapshot: Snapshot) -> Option<Vec<u8>> {
        match self {
            Self::Single(lock) => lock
                .read()
                .read_visible(block, snapshot)
                .map(std::borrow::Cow::into_owned),
            Self::Sharded(store) => store.read_visible(block, snapshot),
        }
    }

    pub(super) fn read_visible_block_buf(
        &self,
        block: BlockNumber,
        snapshot: Snapshot,
    ) -> Option<BlockBuf> {
        match self {
            Self::Single(lock) => lock.read().read_visible_block_buf(block, snapshot),
            Self::Sharded(store) => store.read_visible_block_buf(block, snapshot),
        }
    }

    pub(super) fn current_snapshot(&self) -> Snapshot {
        match self {
            Self::Single(lock) => lock.read().current_snapshot(),
            Self::Sharded(store) => store.current_snapshot(),
        }
    }

    pub(super) fn register_snapshot(&self, snapshot: Snapshot) {
        match self {
            Self::Single(lock) => lock.write().register_snapshot(snapshot),
            Self::Sharded(store) => store.register_snapshot(snapshot),
        }
    }

    pub(super) fn release_snapshot(&self, snapshot: Snapshot) -> bool {
        match self {
            Self::Single(lock) => lock.write().release_snapshot(snapshot),
            Self::Sharded(store) => store.release_snapshot(snapshot),
        }
    }

    pub(super) fn watermark(&self) -> Option<CommitSeq> {
        match self {
            Self::Single(lock) => lock.read().watermark(),
            Self::Sharded(store) => store.watermark(),
        }
    }

    pub(super) fn latest_commit_seq(&self, block: BlockNumber) -> CommitSeq {
        match self {
            Self::Single(lock) => lock.read().latest_commit_seq(block),
            Self::Sharded(store) => store.latest_commit_seq(block),
        }
    }

    pub(super) fn prune_safe(&self) -> CommitSeq {
        match self {
            Self::Single(lock) => lock.write().prune_safe(),
            Self::Sharded(store) => store.prune_safe(),
        }
    }

    pub(super) fn prune_after_commit_if_due(&self, commit_seq: CommitSeq) -> Option<CommitSeq> {
        (commit_seq.0 != 0 && commit_seq.0 % MVCC_COMMIT_PRUNE_INTERVAL == 0)
            .then(|| self.prune_safe())
    }

    pub(super) fn flush_to_device<D: BlockDevice>(&self, cx: &Cx, device: &D) -> FfsResult<usize> {
        match self {
            Self::Single(lock) => lock.read().flush_to_device(cx, device),
            Self::Sharded(store) => store.flush_to_device(cx, device),
        }
    }

    pub(super) fn version_count(&self) -> usize {
        match self {
            Self::Single(lock) => lock.read().version_count(),
            Self::Sharded(store) => store.version_count(),
        }
    }

    pub(super) fn active_snapshot_count(&self) -> usize {
        match self {
            Self::Single(lock) => lock.read().active_snapshot_count(),
            Self::Sharded(store) => store.active_snapshot_count(),
        }
    }

    pub(super) fn block_version_stats(&self) -> BlockVersionStats {
        match self {
            Self::Single(lock) => lock.read().block_version_stats(),
            Self::Sharded(store) => BlockVersionStats {
                tracked_blocks: store.version_count(),
                max_chain_length: 0,
                chains_over_cap: 0,
                chains_over_critical: 0,
                chain_cap: None,
                critical_chain_length: None,
            },
        }
    }

    pub(super) fn ebr_stats(&self) -> EbrVersionStats {
        match self {
            Self::Single(lock) => lock.read().ebr_stats(),
            Self::Sharded(_) => EbrVersionStats::default(),
        }
    }

    pub(super) fn transaction_outcome_stats(&self) -> TransactionOutcomeStats {
        match self {
            Self::Single(lock) => lock.read().transaction_outcome_stats(),
            Self::Sharded(_) => TransactionOutcomeStats::default(),
        }
    }

    pub(super) fn as_single(&self) -> Option<&RwLock<MvccStore>> {
        match self {
            Self::Single(lock) => Some(lock),
            Self::Sharded(_) => None,
        }
    }
}

enum SnapshotOwnership {
    Inline { snapshot: Snapshot },
    Unregistered { snapshot: Snapshot },
}

/// Block-device view over [`FsMvccStore`], preserving the old overlay ordering.
pub struct FsMvccBlockDevice<D: BlockDevice> {
    base: D,
    store: Arc<FsMvccStore>,
    ownership: SnapshotOwnership,
    read_your_writes: bool,
}

impl<D: BlockDevice> FsMvccBlockDevice<D> {
    pub(super) fn new(base: D, store: Arc<FsMvccStore>, snapshot: Snapshot) -> Self {
        store.register_snapshot(snapshot);
        Self {
            base,
            store,
            ownership: SnapshotOwnership::Inline { snapshot },
            read_your_writes: false,
        }
    }

    pub(super) fn new_unregistered(base: D, store: Arc<FsMvccStore>, snapshot: Snapshot) -> Self {
        Self {
            base,
            store,
            ownership: SnapshotOwnership::Unregistered { snapshot },
            read_your_writes: false,
        }
    }

    pub(super) fn with_read_your_writes(mut self) -> Self {
        if let SnapshotOwnership::Inline { snapshot } = self.ownership {
            let released = self.store.release_snapshot(snapshot);
            debug_assert!(
                released,
                "mvcc snapshot was not registered or already released: {snapshot:?}"
            );
            self.ownership = SnapshotOwnership::Unregistered { snapshot };
        }
        self.read_your_writes = true;
        self
    }

    fn snapshot(&self) -> Snapshot {
        match self.ownership {
            SnapshotOwnership::Inline { snapshot }
            | SnapshotOwnership::Unregistered { snapshot } => snapshot,
        }
    }

    fn read_snapshot(&self) -> Snapshot {
        if self.read_your_writes {
            self.store.current_snapshot()
        } else {
            self.snapshot()
        }
    }

    fn reads_base_directly(&self) -> bool {
        matches!(self.ownership, SnapshotOwnership::Unregistered { .. }) && !self.read_your_writes
    }
}

impl<D: BlockDevice> Drop for FsMvccBlockDevice<D> {
    fn drop(&mut self) {
        if let SnapshotOwnership::Inline { snapshot } = self.ownership {
            let released = self.store.release_snapshot(snapshot);
            debug_assert!(
                released,
                "mvcc snapshot was not registered or already released: {snapshot:?}"
            );
        }
    }
}

impl<D: BlockDevice> BlockDevice for FsMvccBlockDevice<D> {
    fn read_block(&self, cx: &Cx, block: BlockNumber) -> FfsResult<BlockBuf> {
        if self.reads_base_directly() {
            return self.base.read_block(cx, block);
        }
        // Read-your-writes for the in-flight op batch (bd-bhh0i): a block this
        // op already staged is not yet in the store overlay, so check it first.
        if op_batch_active() {
            if let Some(bytes) = op_batch_get(block) {
                return Ok(BlockBuf::new(bytes));
            }
        }
        if let Some(buf) = self
            .store
            .read_visible_block_buf(block, self.read_snapshot())
        {
            return Ok(buf);
        }
        self.base.read_block(cx, block)
    }

    fn supports_contiguous_reads(&self) -> bool {
        self.base.supports_contiguous_reads()
    }

    fn read_contiguous_blocks(
        &self,
        cx: &Cx,
        start: BlockNumber,
        bufs: &mut [BlockBuf],
    ) -> FfsResult<()> {
        if bufs.is_empty() {
            return Ok(());
        }
        let count = u64::try_from(bufs.len())
            .map_err(|_| FfsError::Format("block count does not fit u64".to_owned()))?;
        start
            .0
            .checked_add(count)
            .ok_or_else(|| FfsError::Format("block range overflow".to_owned()))?;
        if self.reads_base_directly() {
            return self.base.read_contiguous_blocks(cx, start, bufs);
        }
        // While an op batch is active, a coalesced read could skip a staged
        // block; fall back to per-block reads (overlay-aware). Metadata ops
        // (the only batched callers) issue small reads, so this is rare.
        if op_batch_active() {
            for (delta, buf) in bufs.iter_mut().enumerate() {
                let blk = BlockNumber(start.0 + u64::try_from(delta).unwrap_or(0));
                *buf = self.read_block(cx, blk)?;
            }
            return Ok(());
        }

        let snap = self.read_snapshot();
        let mut visible = Vec::with_capacity(bufs.len());
        let mut any_visible = false;
        for delta in 0..count {
            let block = BlockNumber(start.0 + delta);
            match self.store.read_visible_block_buf(block, snap) {
                Some(buf) => {
                    visible.push(Some(buf));
                    any_visible = true;
                }
                None => visible.push(None),
            }
        }
        if !any_visible {
            return self.base.read_contiguous_blocks(cx, start, bufs);
        }

        let mut idx = 0usize;
        while idx < bufs.len() {
            if let Some(buf) = visible[idx].take() {
                bufs[idx] = buf;
                idx += 1;
                continue;
            }
            let run_start = idx;
            while idx < bufs.len() && visible[idx].is_none() {
                idx += 1;
            }
            let run_start_u64 = u64::try_from(run_start)
                .map_err(|_| FfsError::Format("block range exceeds u64".to_owned()))?;
            let run_block_start = BlockNumber(start.0 + run_start_u64);
            self.base
                .read_contiguous_blocks(cx, run_block_start, &mut bufs[run_start..idx])?;
        }
        Ok(())
    }

    fn read_contiguous_into(&self, cx: &Cx, start: BlockNumber, dst: &mut [u8]) -> FfsResult<()> {
        let bs = self.block_size() as usize;
        if bs == 0 || dst.len() % bs != 0 {
            return Err(FfsError::Format(
                "read_contiguous_into: dst length must be a multiple of block size".to_owned(),
            ));
        }
        if dst.is_empty() {
            return Ok(());
        }
        let count = dst.len() / bs;
        let count_u64 = u64::try_from(count)
            .map_err(|_| FfsError::Format("block range exceeds u64".to_owned()))?;
        start
            .0
            .checked_add(count_u64)
            .ok_or_else(|| FfsError::Format("block range overflow".to_owned()))?;
        if self.reads_base_directly() {
            return self.base.read_contiguous_into(cx, start, dst);
        }
        // Op-batch active: per-block, overlay-aware (see read_contiguous_blocks).
        if op_batch_active() {
            for delta in 0..count {
                let blk = BlockNumber(start.0 + u64::try_from(delta).unwrap_or(0));
                let buf = self.read_block(cx, blk)?;
                dst[delta * bs..(delta + 1) * bs].copy_from_slice(buf.as_slice());
            }
            return Ok(());
        }

        let snap = self.read_snapshot();
        let mut visible = Vec::with_capacity(count);
        let mut any_visible = false;
        for delta in 0..count_u64 {
            let block = BlockNumber(start.0 + delta);
            match self.store.read_visible_block_buf(block, snap) {
                Some(buf) => {
                    visible.push(Some(buf));
                    any_visible = true;
                }
                None => visible.push(None),
            }
        }
        if !any_visible {
            return self.base.read_contiguous_into(cx, start, dst);
        }

        let mut idx = 0usize;
        while idx < count {
            if let Some(buf) = visible[idx].take() {
                dst[idx * bs..(idx + 1) * bs].copy_from_slice(buf.as_slice());
                idx += 1;
                continue;
            }
            let run_start = idx;
            while idx < count && visible[idx].is_none() {
                idx += 1;
            }
            let run_start_u64 = u64::try_from(run_start)
                .map_err(|_| FfsError::Format("block range exceeds u64".to_owned()))?;
            let run_block_start = BlockNumber(start.0 + run_start_u64);
            self.base.read_contiguous_into(
                cx,
                run_block_start,
                &mut dst[run_start * bs..idx * bs],
            )?;
        }
        Ok(())
    }

    fn write_block(&self, _cx: &Cx, block: BlockNumber, data: &[u8]) -> FfsResult<()> {
        if self.reads_base_directly() {
            return Err(FfsError::UnsupportedFeature(
                "unregistered MVCC block device is read-only".to_owned(),
            ));
        }

        // Intra-op batching (bd-bhh0i): stage into the thread-local op batch
        // instead of committing per block. Committed once at op end. Reads on
        // this adapter consult the staged buffer first (read-your-writes).
        if op_batch_active() {
            op_batch_stage(block, data.to_vec());
            return Ok(());
        }

        let mut txn = self.store.begin();
        txn.stage_write(block, data.to_vec());
        let commit_seq = self
            .store
            .commit(txn)
            .map_err(|error| FfsError::Format(error.to_string()))?;
        self.store.prune_after_commit_if_due(commit_seq);
        Ok(())
    }

    fn block_size(&self) -> u32 {
        self.base.block_size()
    }

    fn block_count(&self) -> u64 {
        self.base.block_count()
    }

    fn sync(&self, cx: &Cx) -> FfsResult<()> {
        self.base.sync(cx)
    }
}
