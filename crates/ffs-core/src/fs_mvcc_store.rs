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
        Self::Sharded(ShardedMvccStore::new(8))
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
            debug_assert!(
                self.store.release_snapshot(snapshot),
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

        let mut txn = self.store.begin();
        txn.stage_write(block, data.to_vec());
        self.store
            .commit(txn)
            .map_err(|error| FfsError::Format(error.to_string()))?;
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
