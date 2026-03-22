//! Sharded MVCC version store for concurrent multi-writer access.
//!
//! [`ShardedMvccStore`] partitions block versions across multiple shards,
//! each with its own [`parking_lot::RwLock`].  Writers to different block
//! ranges proceed without contention.  The commit sequence is a global
//! [`AtomicU64`], lock-free for the common case.
//!
//! Snapshot lifecycle is managed externally via [`SnapshotRegistry`].

use crate::SnapshotRegistry;
use crate::compression::{self, CompressionPolicy, VersionData};
use crate::{
    AdaptivePolicyConfig, BlockVersion, CommitError, CommittedTxnRecord, ConflictPolicy,
    ContentionMetrics, MergeProof, Transaction, resolve_version_bytes_at_or_before,
};
use ffs_types::{BlockNumber, CommitSeq, Snapshot, TxnId};
use parking_lot::{RwLock, RwLockWriteGuard};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::{debug, info, trace};

/// A single shard of the version store.
#[derive(Debug, Default)]
struct MvccShard {
    versions: BTreeMap<BlockNumber, Vec<BlockVersion>>,
    /// Per-shard SSI log.  Entries are kept here because SSI checks
    /// are per-block and shards are block-partitioned.
    ssi_log: Vec<CommittedTxnRecord>,
}

type ShardWriteGuard<'a> = RwLockWriteGuard<'a, MvccShard>;

#[derive(Debug, Clone, Copy)]
struct CommitInstallContext {
    snapshot: Snapshot,
    commit_seq: CommitSeq,
    txn_id: TxnId,
    dedup_enabled: bool,
}

/// Thread-safe, sharded MVCC version store.
///
/// Blocks are assigned to shards via `block_number.0 as usize % shard_count`.
/// Each shard has its own `RwLock`, so writers to different block ranges
/// proceed without contention.
///
/// # Snapshot lifecycle
///
/// Use a [`SnapshotRegistry`] (from [`crate`]) alongside this store.
/// The registry tracks active snapshots; the store tracks version chains.
/// This separation avoids coupling snapshot lifecycle to the version-store
/// lock.
///
/// # Commit protocol
///
/// Transactions that touch multiple shards acquire shard locks in sorted
/// order to prevent deadlocks.
#[derive(Debug)]
pub struct ShardedMvccStore {
    shards: Vec<RwLock<MvccShard>>,
    shard_count: usize,
    next_txn: AtomicU64,
    next_commit: AtomicU64,
    /// Latest commit sequence number that has completed installation.
    completed_commit: AtomicU64,
    /// Inline snapshot tracking (for callers who don't use SnapshotRegistry).
    active_snapshots: RwLock<BTreeMap<CommitSeq, u32>>,
    /// Compression policy for version chains.
    compression_policy: CompressionPolicy,
    /// Conflict resolution policy (Strict / SafeMerge / Adaptive).
    conflict_policy: RwLock<ConflictPolicy>,
    /// Configuration for the adaptive expected-loss decision model.
    adaptive_config: AdaptivePolicyConfig,
    /// Runtime contention metrics tracked via EMA (behind a lock for thread safety).
    contention_metrics: RwLock<ContentionMetrics>,
}

impl ShardedMvccStore {
    /// Create a new sharded store with the given shard count.
    ///
    /// A reasonable default is `min(num_cpus, 64)`.
    #[must_use]
    pub fn new(shard_count: usize) -> Self {
        Self::with_compression_policy(shard_count, CompressionPolicy::default())
    }

    /// Create a new sharded store with a custom compression policy.
    #[must_use]
    pub fn with_compression_policy(shard_count: usize, policy: CompressionPolicy) -> Self {
        let shard_count = shard_count.max(1);
        info!(shard_count, "sharded_mvcc_store: initializing");
        let shards = (0..shard_count)
            .map(|_| RwLock::new(MvccShard::default()))
            .collect();
        Self {
            shards,
            shard_count,
            next_txn: AtomicU64::new(1),
            next_commit: AtomicU64::new(1),
            completed_commit: AtomicU64::new(0),
            active_snapshots: RwLock::new(BTreeMap::new()),
            compression_policy: policy,
            conflict_policy: RwLock::new(ConflictPolicy::default()),
            adaptive_config: AdaptivePolicyConfig::default(),
            contention_metrics: RwLock::new(ContentionMetrics::default()),
        }
    }

    /// Number of shards.
    #[must_use]
    pub fn shard_count(&self) -> usize {
        self.shard_count
    }

    /// Set the conflict resolution policy.
    pub fn set_conflict_policy(&self, policy: ConflictPolicy) {
        *self.conflict_policy.write() = policy;
    }

    /// Returns the current conflict policy.
    #[must_use]
    pub fn conflict_policy(&self) -> ConflictPolicy {
        *self.conflict_policy.read()
    }

    /// Returns a snapshot of current contention metrics.
    #[must_use]
    pub fn contention_metrics(&self) -> ContentionMetrics {
        *self.contention_metrics.read()
    }

    /// The effective policy for the next commit: resolves `Adaptive` to a
    /// concrete `Strict` or `SafeMerge` based on current contention metrics.
    #[must_use]
    pub fn effective_policy(&self) -> ConflictPolicy {
        let policy = *self.conflict_policy.read();
        match policy {
            ConflictPolicy::Adaptive => self
                .contention_metrics
                .read()
                .select_policy(&self.adaptive_config),
            other => other,
        }
    }

    /// Map a block number to its shard index.
    #[inline]
    fn shard_index(&self, block: BlockNumber) -> usize {
        let shard_count_u64 = u64::try_from(self.shard_count).expect("shard_count must fit in u64");
        let rem = block.0 % shard_count_u64;
        usize::try_from(rem).expect("remainder must fit in usize")
    }

    fn latest_payload_matches(versions: &[BlockVersion], bytes: &[u8]) -> bool {
        versions.len().checked_sub(1).is_some_and(|last_idx| {
            compression::resolve_data_with(versions, last_idx, |v| &v.data)
                .is_some_and(|existing| existing == bytes)
        })
    }

    fn build_version_data(
        existing_versions: Option<&Vec<BlockVersion>>,
        bytes: Vec<u8>,
        dedup_enabled: bool,
        block: BlockNumber,
    ) -> VersionData {
        if dedup_enabled
            && existing_versions
                .is_some_and(|versions| Self::latest_payload_matches(versions, bytes.as_slice()))
        {
            trace!(
                block = block.0,
                bytes_saved = bytes.len(),
                "sharded_version_dedup"
            );
            VersionData::Identical
        } else {
            VersionData::Full(bytes)
        }
    }

    fn make_chain_head_full(versions: &mut [BlockVersion], keep_from: usize) {
        if keep_from < versions.len() && versions[keep_from].data.is_identical() {
            if let Some(full_data) =
                compression::resolve_data_with(versions, keep_from, |v| &v.data)
            {
                let full_data = full_data.to_vec();
                versions[keep_from].data = VersionData::Full(full_data);
            }
        }
    }

    fn latest_commit_seq_in_shard(shard: &MvccShard, block: BlockNumber) -> CommitSeq {
        shard
            .versions
            .get(&block)
            .and_then(|versions| versions.last())
            .map_or(CommitSeq(0), |version| version.commit_seq)
    }

    fn resolved_write_bytes_locked(
        txn: &Transaction,
        block: BlockNumber,
        shard: &MvccShard,
    ) -> Result<Vec<u8>, CommitError> {
        let staged = txn
            .staged_write(block)
            .expect("write_set keys must have staged bytes");
        let observed = Self::latest_commit_seq_in_shard(shard, block);
        if observed <= txn.snapshot().high {
            return Ok(staged.to_vec());
        }

        let proof = txn.merge_proof(block).cloned().unwrap_or_default();
        let base = shard
            .versions
            .get(&block)
            .and_then(|versions| resolve_version_bytes_at_or_before(versions, txn.snapshot().high))
            .unwrap_or_default();
        let latest = shard
            .versions
            .get(&block)
            .and_then(|versions| resolve_version_bytes_at_or_before(versions, observed))
            .unwrap_or_default();
        proof
            .merge_bytes(&base, &latest, staged)
            .ok_or_else(|| CommitError::Conflict {
                block,
                snapshot: txn.snapshot().high,
                observed,
            })
    }

    fn lock_shards(&self, shard_indices: &[usize]) -> Vec<(usize, ShardWriteGuard<'_>)> {
        shard_indices
            .iter()
            .map(|&idx| (idx, self.shards[idx].write()))
            .collect()
    }

    fn preflight_fcw_locked(
        &self,
        txn: &Transaction,
        shard_guards: &[(usize, ShardWriteGuard<'_>)],
        merge_log_event: &'static str,
    ) -> Result<(), CommitError> {
        let effective = self.effective_policy();
        let mut had_conflict = false;
        let mut merge_succeeded = false;

        for &block in txn.write_set().keys() {
            let shard_idx = self.shard_index(block);
            let shard = shard_guards
                .iter()
                .find(|(idx, _)| *idx == shard_idx)
                .map(|(_, guard)| guard)
                .expect("shard must be locked");
            let latest = Self::latest_commit_seq_in_shard(shard, block);
            if latest > txn.snapshot().high {
                had_conflict = true;

                // Under Strict policy, any conflict is an immediate abort.
                if effective == ConflictPolicy::Strict {
                    self.contention_metrics.write().record_commit(
                        self.adaptive_config.ema_alpha,
                        true,
                        false,
                        true,
                    );
                    return Err(CommitError::Conflict {
                        block,
                        snapshot: txn.snapshot().high,
                        observed: latest,
                    });
                }

                // SafeMerge: attempt merge-proof resolution.
                if Self::resolved_write_bytes_locked(txn, block, shard).is_ok() {
                    merge_succeeded = true;
                    debug!(
                        block = block.0,
                        merge_proof = ?txn.merge_proof(block),
                        snapshot_commit_seq = txn.snapshot().high.0,
                        observed_commit_seq = latest.0,
                        policy = ?effective,
                        "{merge_log_event}"
                    );
                } else {
                    self.contention_metrics.write().record_commit(
                        self.adaptive_config.ema_alpha,
                        true,
                        false,
                        true,
                    );
                    return Err(CommitError::Conflict {
                        block,
                        snapshot: txn.snapshot().high,
                        observed: latest,
                    });
                }
            }
        }

        // Record successful preflight (no abort).
        self.contention_metrics.write().record_commit(
            self.adaptive_config.ema_alpha,
            had_conflict,
            merge_succeeded,
            false,
        );
        Ok(())
    }

    fn merged_write_bytes_locked(
        shard: &MvccShard,
        block: BlockNumber,
        snapshot: Snapshot,
        bytes: Vec<u8>,
        merge_proof: Option<&MergeProof>,
    ) -> Vec<u8> {
        let observed = Self::latest_commit_seq_in_shard(shard, block);
        if observed <= snapshot.high {
            return bytes;
        }

        let proof = merge_proof.cloned().unwrap_or_default();
        let base = shard
            .versions
            .get(&block)
            .and_then(|versions| resolve_version_bytes_at_or_before(versions, snapshot.high))
            .unwrap_or_default();
        let latest = shard
            .versions
            .get(&block)
            .and_then(|versions| resolve_version_bytes_at_or_before(versions, observed))
            .unwrap_or_default();
        proof
            .merge_bytes(&base, &latest, &bytes)
            .expect("preflight must reject unmergeable conflicts")
    }

    fn install_committed_version_locked(
        shard: &mut MvccShard,
        block: BlockNumber,
        bytes: Vec<u8>,
        merge_proof: Option<&MergeProof>,
        ctx: CommitInstallContext,
    ) {
        let version_bytes =
            Self::merged_write_bytes_locked(shard, block, ctx.snapshot, bytes, merge_proof);
        let version_data = Self::build_version_data(
            shard.versions.get(&block),
            version_bytes,
            ctx.dedup_enabled,
            block,
        );
        let versions = shard.versions.entry(block).or_default();
        let pos = versions.partition_point(|v| v.commit_seq < ctx.commit_seq);
        versions.insert(
            pos,
            BlockVersion {
                block,
                commit_seq: ctx.commit_seq,
                writer: ctx.txn_id,
                data: version_data,
            },
        );
    }

    fn ssi_shards_for_txn(&self, txn: &Transaction) -> Vec<usize> {
        let mut shard_indices = BTreeSet::new();
        for block in txn.write_set().keys() {
            shard_indices.insert(self.shard_index(*block));
        }
        for block in txn.read_set().keys() {
            shard_indices.insert(self.shard_index(*block));
        }
        shard_indices.into_iter().collect()
    }

    fn validate_ssi_read_set_locked(
        &self,
        txn: &Transaction,
        shard_guards: &[(usize, ShardWriteGuard<'_>)],
    ) -> Result<(), CommitError> {
        for (&block, &read_version) in txn.read_set() {
            let shard_idx = self.shard_index(block);
            let shard = shard_guards
                .iter()
                .find(|(idx, _)| *idx == shard_idx)
                .map(|(_, guard)| guard)
                .expect("shard must be locked");
            for record in shard.ssi_log.iter().rev() {
                if record.commit_seq <= txn.snapshot().high {
                    break;
                }
                if record.write_set.contains(&block) {
                    return Err(CommitError::SsiConflict {
                        pivot_block: block,
                        read_version,
                        write_version: record.commit_seq,
                        concurrent_txn: record.txn_id,
                    });
                }
            }
        }
        Ok(())
    }

    fn append_ssi_record_locked(
        shard_guards: &mut [(usize, ShardWriteGuard<'_>)],
        record: &CommittedTxnRecord,
    ) {
        for (_, shard) in shard_guards {
            shard.ssi_log.push(record.clone());
        }
    }

    /// The current snapshot (latest committed version).
    #[must_use]
    pub fn current_snapshot(&self) -> Snapshot {
        let high = self.completed_commit.load(Ordering::Acquire);
        Snapshot {
            high: CommitSeq(high),
        }
    }

    /// Begin a new transaction at the current snapshot.
    pub fn begin(&self) -> Transaction {
        let id = TxnId(self.next_txn.fetch_add(1, Ordering::SeqCst));
        let snapshot = self.current_snapshot();
        Transaction::new(id, snapshot)
    }

    /// The latest commit sequence for a block (per-shard query).
    #[must_use]
    pub fn latest_commit_seq(&self, block: BlockNumber) -> CommitSeq {
        let shard_idx = self.shard_index(block);
        let shard = self.shards[shard_idx].read();
        shard
            .versions
            .get(&block)
            .and_then(|v| v.last())
            .map_or(CommitSeq(0), |v| v.commit_seq)
    }

    /// Read the version of `block` visible at `snapshot`.
    #[must_use]
    pub fn read_visible(&self, block: BlockNumber, snapshot: Snapshot) -> Option<Vec<u8>> {
        let shard_idx = self.shard_index(block);
        let shard = self.shards[shard_idx].read();
        shard.versions.get(&block).and_then(|versions| {
            let idx = versions
                .iter()
                .rposition(|v| v.commit_seq <= snapshot.high)?;
            compression::resolve_data_with(versions, idx, |v| &v.data)
                .map(std::borrow::Cow::into_owned)
        })
    }

    /// Commit a transaction with first-committer-wins (FCW) conflict detection.
    ///
    /// Shard locks are acquired in sorted order to prevent deadlocks.
    #[allow(clippy::result_large_err)]
    pub fn commit(&self, txn: Transaction) -> Result<CommitSeq, (CommitError, Transaction)> {
        if txn.write_set().is_empty() {
            // Read-only transaction: nothing to commit.
            return Ok(self.current_snapshot().high);
        }

        let shard_indices = self.involved_shards(&txn);
        let mut shard_guards = self.lock_shards(&shard_indices);

        if let Err(error) =
            self.preflight_fcw_locked(&txn, &shard_guards, "sharded_fcw_conflict_merged")
        {
            return Err((error, txn));
        }

        let commit_seq = CommitSeq(self.next_commit.fetch_add(1, Ordering::SeqCst));
        trace!(
            commit_seq = commit_seq.0,
            shards_involved = shard_indices.len(),
            blocks_written = txn.write_set().len(),
            "sharded_commit"
        );

        let install_ctx = CommitInstallContext {
            snapshot: txn.snapshot(),
            commit_seq,
            txn_id: txn.id(),
            dedup_enabled: self.compression_policy.dedup_identical,
        };
        let (writes, merge_proofs) = txn.into_writes_and_merge_proofs();
        for (block, bytes) in writes {
            let shard_idx = self.shard_index(block);
            let shard = shard_guards
                .iter_mut()
                .find(|(idx, _)| *idx == shard_idx)
                .map(|(_, guard)| guard)
                .expect("shard must be locked");
            Self::install_committed_version_locked(
                shard,
                block,
                bytes,
                merge_proofs.get(&block),
                install_ctx,
            );
        }

        // Wait for previous transactions to complete before publishing our commit_seq.
        while self.completed_commit.load(Ordering::Acquire) != commit_seq.0.saturating_sub(1) {
            std::thread::yield_now();
        }
        self.completed_commit.store(commit_seq.0, Ordering::Release);

        Ok(commit_seq)
    }

    /// Commit with Serializable Snapshot Isolation (SSI) enforcement.
    #[allow(clippy::result_large_err)]
    pub fn commit_ssi(&self, txn: Transaction) -> Result<CommitSeq, (CommitError, Transaction)> {
        if txn.write_set().is_empty() {
            return Ok(self.current_snapshot().high);
        }

        let shard_indices = self.ssi_shards_for_txn(&txn);
        let mut shard_guards = self.lock_shards(&shard_indices);

        if let Err(error) =
            self.preflight_fcw_locked(&txn, &shard_guards, "sharded_ssi_fcw_conflict_merged")
        {
            return Err((error, txn));
        }

        if let Err(error) = self.validate_ssi_read_set_locked(&txn, &shard_guards) {
            return Err((error, txn));
        }

        let commit_seq = CommitSeq(self.next_commit.fetch_add(1, Ordering::SeqCst));
        let install_ctx = CommitInstallContext {
            snapshot: txn.snapshot(),
            commit_seq,
            txn_id: txn.id(),
            dedup_enabled: self.compression_policy.dedup_identical,
        };
        let read_set = txn.read_set().clone();
        let write_keys: BTreeSet<BlockNumber> = txn.write_set().keys().copied().collect();

        let (writes, merge_proofs) = txn.into_writes_and_merge_proofs();
        for (block, bytes) in writes {
            let shard_idx = self.shard_index(block);
            let shard = shard_guards
                .iter_mut()
                .find(|(idx, _)| *idx == shard_idx)
                .map(|(_, guard)| guard)
                .expect("shard must be locked");
            Self::install_committed_version_locked(
                shard,
                block,
                bytes,
                merge_proofs.get(&block),
                install_ctx,
            );
        }

        let ssi_record = CommittedTxnRecord {
            txn_id: install_ctx.txn_id,
            commit_seq,
            snapshot: install_ctx.snapshot,
            write_set: write_keys,
            read_set,
        };
        Self::append_ssi_record_locked(&mut shard_guards, &ssi_record);

        // Wait for previous transactions to complete before publishing our commit_seq.
        while self.completed_commit.load(Ordering::Acquire) != commit_seq.0.saturating_sub(1) {
            std::thread::yield_now();
        }
        self.completed_commit.store(commit_seq.0, Ordering::Release);

        Ok(commit_seq)
    }

    // ── Snapshot tracking (inline, for compatibility) ────────────────────

    /// Register a snapshot as active (inline tracking).
    pub fn register_snapshot(&self, snapshot: Snapshot) {
        let mut active = self.active_snapshots.write();
        *active.entry(snapshot.high).or_insert(0) += 1;
    }

    /// Release a previously registered snapshot.
    pub fn release_snapshot(&self, snapshot: Snapshot) -> bool {
        let mut active = self.active_snapshots.write();
        active.get(&snapshot.high).copied().is_some_and(|count| {
            if count <= 1 {
                active.remove(&snapshot.high);
            } else {
                active.insert(snapshot.high, count - 1);
            }
            true
        })
    }

    /// Oldest active snapshot, or `None`.
    #[must_use]
    pub fn watermark(&self) -> Option<CommitSeq> {
        self.active_snapshots.read().keys().next().copied()
    }

    /// Number of active snapshot references.
    #[must_use]
    pub fn active_snapshot_count(&self) -> usize {
        self.active_snapshots
            .read()
            .values()
            .map(|c| *c as usize)
            .sum()
    }

    // ── GC / pruning ────────────────────────────────────────────────────

    /// Prune versions older than `watermark` across all shards.
    pub fn prune_versions_older_than(&self, watermark: CommitSeq) {
        for (idx, shard_lock) in self.shards.iter().enumerate() {
            let mut shard = shard_lock.write();
            for versions in shard.versions.values_mut() {
                if versions.len() <= 1 {
                    continue;
                }
                let mut keep_from = 0_usize;
                while keep_from + 1 < versions.len() {
                    if versions[keep_from + 1].commit_seq <= watermark {
                        keep_from += 1;
                    } else {
                        break;
                    }
                }
                if keep_from > 0 {
                    Self::make_chain_head_full(versions, keep_from);
                    versions.drain(0..keep_from);
                }
            }
            // Prune SSI log for this shard too.
            shard.ssi_log.retain(|r| r.commit_seq > watermark);
            drop(shard);
            trace!(shard_idx = idx, watermark = watermark.0, "shard_pruned");
        }
    }

    /// Safe prune: use watermark from active snapshots.
    ///
    /// Holds the `active_snapshots` write lock while pruning to prevent a
    /// TOCTOU race where a snapshot is registered between reading the
    /// watermark and pruning versions older than it.
    pub fn prune_safe(&self) -> CommitSeq {
        let active = self.active_snapshots.write();
        let wm = active
            .keys()
            .next()
            .copied()
            .unwrap_or_else(|| self.current_snapshot().high);
        // Hold the active_snapshots lock while pruning so no new snapshot
        // can be registered at a commit_seq that we're about to prune.
        self.prune_versions_older_than(wm);
        drop(active);
        debug!(watermark = wm.0, "prune_safe_sharded");
        wm
    }

    /// Safe prune using an external [`SnapshotRegistry`].
    pub fn prune_safe_with_registry(&self, registry: &SnapshotRegistry) -> CommitSeq {
        let wm = registry
            .watermark()
            .unwrap_or_else(|| self.current_snapshot().high);
        self.prune_versions_older_than(wm);
        debug!(watermark = wm.0, "prune_safe_registry");
        wm
    }

    /// Total number of block versions across all shards.
    #[must_use]
    pub fn version_count(&self) -> usize {
        self.shards
            .iter()
            .map(|s| s.read().versions.values().map(Vec::len).sum::<usize>())
            .sum()
    }

    /// Number of distinct versioned blocks across all shards.
    #[must_use]
    pub fn block_count_versioned(&self) -> usize {
        self.shards.iter().map(|s| s.read().versions.len()).sum()
    }

    // ── Internals ───────────────────────────────────────────────────────

    /// Sorted, deduplicated shard indices touched by a transaction's writes.
    fn involved_shards(&self, txn: &Transaction) -> Vec<usize> {
        let mut indices: BTreeSet<usize> = BTreeSet::new();
        for block in txn.write_set().keys() {
            indices.insert(self.shard_index(*block));
        }
        indices.into_iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn make_store(shards: usize) -> ShardedMvccStore {
        ShardedMvccStore::new(shards)
    }

    #[test]
    fn basic_commit_and_read() {
        let store = make_store(4);
        let mut txn = store.begin();
        txn.stage_write(BlockNumber(1), vec![0xAA; 8]);
        let seq = store.commit(txn).expect("commit");
        assert_eq!(seq, CommitSeq(1));

        let snap = store.current_snapshot();
        let data = store.read_visible(BlockNumber(1), snap).expect("visible");
        assert_eq!(data, vec![0xAA; 8]);
    }

    #[test]
    fn fcw_conflict_same_block() {
        let store = make_store(4);
        let mut t1 = store.begin();
        let mut t2 = store.begin();

        t1.stage_write(BlockNumber(7), vec![1]);
        t2.stage_write(BlockNumber(7), vec![2]);

        store.commit(t1).expect("t1");
        let err = store.commit(t2).expect_err("t2 should conflict");
        assert!(matches!(err, (CommitError::Conflict { .. }, _)));
    }

    #[test]
    fn fcw_append_only_merge_proof_allows_same_block_commit() {
        let store = make_store(4);
        let block = BlockNumber(9);

        let mut seed = store.begin();
        seed.stage_write(block, vec![0]);
        store.commit(seed).expect("seed");

        let mut t1 = store.begin();
        let mut t2 = store.begin();

        t1.stage_write_with_proof(
            block,
            vec![0, 1],
            crate::MergeProof::AppendOnly { base_len: 1 },
        );
        t2.stage_write_with_proof(
            block,
            vec![0, 2],
            crate::MergeProof::AppendOnly { base_len: 1 },
        );

        store.commit(t1).expect("first append");
        store
            .commit(t2)
            .expect("second append should merge instead of conflicting");

        let latest = store.current_snapshot();
        let visible = store.read_visible(block, latest).expect("visible");
        assert_eq!(visible, vec![0, 1, 2]);
    }

    #[test]
    fn disjoint_shards_no_conflict() {
        let store = make_store(4);
        let mut t1 = store.begin();
        let mut t2 = store.begin();

        // These go to different shards (0%4=0, 1%4=1).
        t1.stage_write(BlockNumber(0), vec![1]);
        t2.stage_write(BlockNumber(1), vec![2]);

        store.commit(t1).expect("t1");
        store
            .commit(t2)
            .expect("t2 should succeed (different shard)");
    }

    #[test]
    fn snapshot_isolation() {
        let store = make_store(4);

        let mut t1 = store.begin();
        t1.stage_write(BlockNumber(1), vec![1]);
        store.commit(t1).expect("commit v1");

        let snap = store.current_snapshot();

        let mut t2 = store.begin();
        t2.stage_write(BlockNumber(1), vec![2]);
        store.commit(t2).expect("commit v2");

        // Snap should still see v1.
        let data = store.read_visible(BlockNumber(1), snap).expect("visible");
        assert_eq!(data, vec![1]);

        // Latest should see v2.
        let latest = store.current_snapshot();
        let data2 = store.read_visible(BlockNumber(1), latest).expect("visible");
        assert_eq!(data2, vec![2]);
    }

    #[test]
    fn commit_sequence_advances_atomically() {
        let store = make_store(4);

        for i in 1_u64..=10 {
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(i), vec![u8::try_from(i).expect("i fits in u8")]);
            let seq = store.commit(txn).expect("commit");
            assert_eq!(seq, CommitSeq(i));
        }
    }

    #[test]
    fn ssi_detects_write_skew() {
        let store = make_store(4);
        let block_a = BlockNumber(100);
        let block_b = BlockNumber(200);

        // Seed.
        let mut seed = store.begin();
        seed.stage_write(block_a, vec![1]);
        seed.stage_write(block_b, vec![1]);
        store.commit_ssi(seed).expect("seed");

        // T1: reads A, writes B.
        let mut t1 = store.begin();
        let a_ver = store.latest_commit_seq(block_a);
        t1.record_read(block_a, a_ver);
        t1.stage_write(block_b, vec![2]);

        // T2: reads B, writes A.
        let mut t2 = store.begin();
        let b_ver = store.latest_commit_seq(block_b);
        t2.record_read(block_b, b_ver);
        t2.stage_write(block_a, vec![2]);

        store.commit_ssi(t1).expect("T1 succeeds");
        let result = store.commit_ssi(t2);
        assert!(
            matches!(result, Err((CommitError::SsiConflict { .. }, _))),
            "SSI should reject T2"
        );
    }

    #[test]
    fn prune_across_shards() {
        let store = make_store(4);

        // Write to 4 different shards.
        for i in 0_u64..4 {
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(i), vec![1]);
            store.commit(txn).expect("commit");
        }
        // Write second version to all.
        for i in 0_u64..4 {
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(i), vec![2]);
            store.commit(txn).expect("commit");
        }

        assert_eq!(store.version_count(), 8);

        store.prune_safe();

        // Should keep only latest version per block.
        assert!(store.version_count() <= 4);
    }

    #[test]
    fn concurrent_writes_different_shards() {
        let store = Arc::new(ShardedMvccStore::new(8));
        let num_threads = 8_usize;
        let barrier = Arc::new(std::sync::Barrier::new(num_threads));

        let handles: Vec<_> = (0..num_threads)
            .map(|i| {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    // Each thread writes to its own block (different shard).
                    let block = BlockNumber(u64::try_from(i).unwrap());
                    let mut txn = store.begin();
                    let val = u8::try_from(i % 256).unwrap();
                    txn.stage_write(block, vec![val; 64]);
                    store.commit(txn).expect("commit should succeed");
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread panicked");
        }

        let snap = store.current_snapshot();
        for i in 0..num_threads {
            let block = BlockNumber(u64::try_from(i).unwrap());
            let val = u8::try_from(i % 256).unwrap();
            let data = store.read_visible(block, snap).expect("visible");
            assert_eq!(data, vec![val; 64]);
        }
    }

    #[test]
    fn concurrent_writes_same_shard_serialize() {
        let store = Arc::new(ShardedMvccStore::new(1)); // Single shard forces serialization.
        let num_threads = 8_usize;
        let barrier = Arc::new(std::sync::Barrier::new(num_threads));

        let handles: Vec<_> = (0..num_threads)
            .map(|i| {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    // All write to different blocks but same shard.
                    let block = BlockNumber(u64::try_from(i).unwrap());
                    let mut txn = store.begin();
                    let value = u8::try_from(i).expect("i fits in u8");
                    txn.stage_write(block, vec![value; 8]);
                    store
                        .commit(txn)
                        .expect("should succeed (different blocks)");
                })
            })
            .collect();

        for h in handles {
            h.join().expect("thread panicked");
        }

        // All writes should be visible.
        let snap = store.current_snapshot();
        for i in 0..num_threads {
            let block = BlockNumber(u64::try_from(i).unwrap());
            let data = store.read_visible(block, snap).expect("visible");
            let value = u8::try_from(i).expect("i fits in u8");
            assert_eq!(data, vec![value; 8]);
        }
    }

    #[test]
    fn snapshot_reads_consistent_across_shards() {
        let store = ShardedMvccStore::new(4);

        // Write to 4 different shards in one commit.
        let mut txn = store.begin();
        for i in 0_u64..4 {
            txn.stage_write(BlockNumber(i), vec![1; 8]);
        }
        store.commit(txn).expect("commit");

        let snap = store.current_snapshot();

        // Write v2 to all.
        let mut txn2 = store.begin();
        for i in 0_u64..4 {
            txn2.stage_write(BlockNumber(i), vec![2; 8]);
        }
        store.commit(txn2).expect("commit");

        // Snap should see v1 across all shards.
        for i in 0_u64..4 {
            let data = store.read_visible(BlockNumber(i), snap).expect("visible");
            assert_eq!(data, vec![1; 8], "block {i} should see v1 at old snapshot");
        }
    }

    #[test]
    fn stress_16_threads_10000_ops() {
        let store = Arc::new(ShardedMvccStore::new(8));
        let num_threads = 16_usize;
        let ops_per_thread = 10_000_usize;
        let barrier = Arc::new(std::sync::Barrier::new(num_threads));

        let handles: Vec<_> = (0..num_threads)
            .map(|thread_id| {
                let store = Arc::clone(&store);
                let barrier = Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    let mut committed = 0_usize;
                    for j in 0..ops_per_thread {
                        let block_num = u64::try_from(thread_id * ops_per_thread + j).unwrap() % 64;
                        let block = BlockNumber(block_num);
                        let mut txn = store.begin();
                        let value = u8::try_from(j % 256).expect("j % 256 always fits in u8");
                        txn.stage_write(block, vec![value; 8]);
                        match store.commit(txn) {
                            Ok(_) => committed += 1,
                            Err((CommitError::Conflict { .. }, _)) => {
                                // Expected under contention.
                            }
                            Err((e, _)) => panic!("unexpected error: {e}"),
                        }
                    }
                    committed
                })
            })
            .collect();

        let mut total_committed = 0_usize;
        for handle in handles {
            total_committed += handle.join().expect("thread panicked");
        }

        // At least some should have committed.
        assert!(total_committed > 0, "at least some commits should succeed");

        // Version store should be consistent.
        let snap = store.current_snapshot();
        for b in 0_u64..64 {
            // Every block that has a version should be readable.
            if let Some(data) = store.read_visible(BlockNumber(b), snap) {
                assert_eq!(data.len(), 8);
            }
        }
    }

    #[test]
    fn prune_with_external_registry() {
        let store = ShardedMvccStore::new(4);
        let registry = Arc::new(SnapshotRegistry::new());

        // Write 3 versions to block 0.
        for v in 1_u8..=3 {
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(0), vec![v]);
            store.commit(txn).expect("commit");
        }

        // Register a snapshot at commit 2.
        let snap2 = Snapshot { high: CommitSeq(2) };
        let _handle = SnapshotRegistry::acquire(&registry, snap2);

        // Prune using registry watermark.
        let wm = store.prune_safe_with_registry(&registry);
        assert_eq!(wm, CommitSeq(2));

        // v2 should still be visible.
        let data = store.read_visible(BlockNumber(0), snap2).expect("visible");
        assert_eq!(data, vec![2]);
    }

    #[test]
    fn multi_shard_transaction() {
        let store = ShardedMvccStore::new(4);

        // Write to blocks that span all 4 shards in a single transaction.
        let mut txn = store.begin();
        txn.stage_write(BlockNumber(0), vec![10]); // shard 0
        txn.stage_write(BlockNumber(1), vec![11]); // shard 1
        txn.stage_write(BlockNumber(2), vec![12]); // shard 2
        txn.stage_write(BlockNumber(3), vec![13]); // shard 3
        let seq = store.commit(txn).expect("multi-shard commit");

        let snap = store.current_snapshot();
        assert_eq!(store.read_visible(BlockNumber(0), snap).unwrap(), vec![10]);
        assert_eq!(store.read_visible(BlockNumber(3), snap).unwrap(), vec![13]);
        assert_eq!(seq, CommitSeq(1));
    }

    // ── Property-based tests (proptest) ────────────────────────────────────

    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Shard index is always in [0, shard_count).
        #[test]
        fn proptest_shard_index_in_range(
            shard_count in 1_usize..64,
            block_num in any::<u64>(),
        ) {
            let store = make_store(shard_count);
            let idx = store.shard_index(BlockNumber(block_num));
            prop_assert!(idx < shard_count, "shard_index {} >= {}", idx, shard_count);
        }

        /// Committed writes are visible in ShardedMvccStore.
        #[test]
        fn proptest_sharded_committed_writes_visible(
            shard_count in 1_usize..8,
            ops in proptest::collection::vec((0_u16..64, any::<u8>()), 1..16),
        ) {
            let store = make_store(shard_count);
            let mut expected = std::collections::BTreeMap::<u16, u8>::new();
            let mut txn = store.begin();
            for &(block, byte) in &ops {
                txn.stage_write(BlockNumber(u64::from(block)), vec![byte; 8]);
                expected.insert(block, byte);
            }
            store.commit(txn).expect("commit");

            let snap = store.current_snapshot();
            for (&block, &byte) in &expected {
                let data = store
                    .read_visible(BlockNumber(u64::from(block)), snap)
                    .expect("visible");
                prop_assert_eq!(data[0], byte, "block {} data mismatch", block);
            }
        }

        /// FCW conflict detection in ShardedMvccStore.
        #[test]
        fn proptest_sharded_fcw_conflict(
            shard_count in 1_usize..8,
            block_id in 0_u64..64,
            byte_a in any::<u8>(),
            byte_b in any::<u8>(),
        ) {
            let store = make_store(shard_count);
            let block = BlockNumber(block_id);
            let mut t1 = store.begin();
            let mut t2 = store.begin();
            t1.stage_write(block, vec![byte_a; 8]);
            t2.stage_write(block, vec![byte_b; 8]);
            store.commit(t1).expect("t1 first");
            let result = store.commit(t2);
            prop_assert!(result.is_err(), "FCW should reject t2 for block {}", block_id);
        }

        /// Snapshot isolation in ShardedMvccStore.
        #[test]
        fn proptest_sharded_snapshot_isolation(
            shard_count in 1_usize..8,
            block_id in 0_u64..32,
            byte_v1 in any::<u8>(),
            byte_v2 in any::<u8>(),
        ) {
            let store = make_store(shard_count);
            let block = BlockNumber(block_id);

            let mut t1 = store.begin();
            t1.stage_write(block, vec![byte_v1; 8]);
            store.commit(t1).expect("commit v1");

            let snap = store.current_snapshot();

            let mut t2 = store.begin();
            t2.stage_write(block, vec![byte_v2; 8]);
            store.commit(t2).expect("commit v2");

            // snap must still see v1
            let data = store.read_visible(block, snap).expect("visible");
            prop_assert_eq!(data[0], byte_v1);
        }

        /// Snapshot register/release ref-counting in ShardedMvccStore.
        #[test]
        fn proptest_sharded_snapshot_refcount(
            register_count in 1_usize..8,
        ) {
            let store = make_store(4);
            let mut txn = store.begin();
            txn.stage_write(BlockNumber(0), vec![1]);
            store.commit(txn).expect("commit");

            let snap = store.current_snapshot();
            for _ in 0..register_count {
                store.register_snapshot(snap);
            }
            prop_assert_eq!(store.active_snapshot_count(), register_count);
            prop_assert_eq!(store.watermark(), Some(snap.high));

            for _ in 0..register_count {
                prop_assert!(store.release_snapshot(snap));
            }
            prop_assert_eq!(store.active_snapshot_count(), 0);
            prop_assert_eq!(store.watermark(), None);
        }

        /// Unwritten blocks return None in ShardedMvccStore.
        #[test]
        fn proptest_sharded_unwritten_returns_none(
            shard_count in 1_usize..8,
            block_id in 0_u64..1024,
        ) {
            let store = make_store(shard_count);
            let snap = store.current_snapshot();
            prop_assert!(store.read_visible(BlockNumber(block_id), snap).is_none());
        }
    }
}
